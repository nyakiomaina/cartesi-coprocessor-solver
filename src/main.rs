use alloy::signers::k256::SecretKey;
use alloy_contract::Event;
use alloy_primitives::{keccak256, Address, FixedBytes, Keccak256, B256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::Filter;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use alloy_sol_types::sol;
use ark_serialize::CanonicalDeserialize;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use eigen_client_avsregistry::reader::AvsRegistryChainReader;
use eigen_crypto_bls::{
    convert_to_bls_checker_g1_point, convert_to_bls_checker_g2_point, Signature,
};
use eigen_logging::{log_level::LogLevel, tracing_logger::TracingLogger};
use eigen_services_avsregistry::{chaincaller::AvsRegistryServiceChainCaller, AvsRegistryService};
use eigen_services_blsaggregation::bls_agg::{BlsAggregationServiceResponse, BlsAggregatorService};
use eigen_services_operatorsinfo::operatorsinfo_inmemory::OperatorInfoServiceInMemory;
use eigen_types::operator::OperatorAvsState;
use eigen_utils::{
    get_provider,
    iblssignaturechecker::{
        IBLSSignatureChecker::{self, NonSignerStakesAndSignature},
        BN254::G1Point,
    },
};
use futures_util::FutureExt;
use futures_util::{StreamExt, TryStreamExt};
use hex::FromHex;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server, StatusCode,
};
use serde::Deserialize;
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::Mutex,
    task::{self, JoinHandle},
};
use tokio_postgres::{AsyncMessage, NoTls};
use tokio_util::sync::CancellationToken;
use ICoprocessor::TaskIssued;
mod outputs_merkle;
use alloy_network::EthereumWallet;
use futures_util::stream;
use tokio_postgres::types::{FromSql, ToSql};
use cartesi_coprocessor_contracts::{
    l1_coprocessor::{L1Coprocessor, Response as L1Response},
    l2_coprocessor::{L2Coprocessor, Response as L2Response},
    icrossdomainmessenger::ICrossDomainMessenger,
    icoprocessor::ICoprocessorEvents,
};

const HEIGHT: usize = 63;
const TASK_INDEX: u32 = 1;
#[derive(Deserialize)]
struct Config {
    http_endpoint: String,
    ws_endpoint: String,
    registry_coordinator_address: Address,
    operator_state_retriever_address: Address,
    current_first_block: u64,
    task_issuer: Address,
    ruleset: String,
    socket: String,
    secret_key: String,
    payment_phrase: String,
    postgre_connect_request: String,
    payment_token: Address,
    l2_http_endpoint: String,
    l2_ws_endpoint: String,
    l2_coprocessor_address: Address,
    l1_http_endpoint: String,
    l1_ws_endpoint: String,
    l1_coprocessor_address: Address,
    cross_domain_messenger_address: Address,
}
#[derive(Debug, ToSql, FromSql, PartialEq)]
enum task_status {
    handled,
    in_progress,
    waits_for_handling,
}
#[tokio::main]
async fn main() {
    let config_string = std::fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config_string).unwrap();
    let manager =
        PostgresConnectionManager::new(config.postgre_connect_request.parse().unwrap(), NoTls);

    let pool = Pool::builder().build(manager).await.unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "
            DO $$ BEGIN
                CREATE TYPE task_status AS ENUM ('handled', 'in_progress', 'waits_for_handling');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
       ",
            &[],
        )
        .await
        .unwrap();
    client
        .batch_execute(
            "
        CREATE TABLE IF NOT EXISTS issued_tasks (
            id SERIAL PRIMARY KEY,
            machineHash BYTEA,
            input BYTEA,
            callback BYTEA,
            status task_status
        )
 ",
        )
        .await
        .unwrap();
    client
        .batch_execute(
            "
        CREATE UNIQUE INDEX IF NOT EXISTS unique_machine_input_callback
        ON issued_tasks ((machineHash || input || callback))
",
        )
        .await
        .unwrap();

    client
        .batch_execute("CREATE TABLE IF NOT EXISTS machine_hashes (id SERIAL PRIMARY KEY, machine_hash BYTEA UNIQUE)").await.unwrap();

    println!("Starting solver..");
    let arc_ws_endpoint = Arc::new(config.ws_endpoint.clone());

    let tracing_logger =
        TracingLogger::new_text_logger(false, String::from(""), LogLevel::Debug, false);
    let avs_registry_reader = AvsRegistryChainReader::new(
        tracing_logger.clone(),
        config.registry_coordinator_address,
        config.operator_state_retriever_address,
        config.http_endpoint.clone(),
    )
    .await
    .unwrap();

    let operators_info = OperatorInfoServiceInMemory::new(
        tracing_logger.clone(),
        avs_registry_reader.clone(),
        config.ws_endpoint.clone(),
    )
    .await;
    let avs_registry_service =
        AvsRegistryServiceChainCaller::new(avs_registry_reader, operators_info.clone());

    let cancellation_token = CancellationToken::new();
    let operators_info_clone = Arc::new(operators_info.clone());
    let token_clone = cancellation_token.clone();
    let provider =
        alloy_provider::ProviderBuilder::new().on_http(config.http_endpoint.parse().unwrap());
    let current_block_num = provider.get_block_number().await.unwrap();
    println!("current_block_num {:?}", current_block_num);

    let l2_provider = ProviderBuilder::new().on_http(config.l2_http_endpoint.parse().unwrap());
    let l2_ws_provider = ProviderBuilder::new().on_ws(config.l2_ws_endpoint.parse().unwrap()).await.unwrap();

    let l1_provider = ProviderBuilder::new().on_http(config.l1_http_endpoint.parse().unwrap());
    let l1_ws_provider = ProviderBuilder::new().on_ws(config.l1_ws_endpoint.parse().unwrap()).await.unwrap();

    let l2_coprocessor_address = Address::parse_checksummed(&config.l2_coprocessor_address, None).unwrap();
    let l1_coprocessor_address = Address::parse_checksummed(&config.l1_coprocessor_address, None).unwrap();
    let cross_domain_messenger_address = Address::parse_checksummed(&config.cross_domain_messenger_address, None).unwrap();

    let l2_coprocessor = L2Coprocessor::new(l2_coprocessor_address, &l2_provider);
    let l1_coprocessor = L1Coprocessor::new(l1_coprocessor_address, &l1_provider);
    le

    task::spawn({
        let arc_operators_info = operators_info_clone.clone();
        async move {
            arc_operators_info
                .start_service(&token_clone, config.current_first_block, current_block_num)
                .await
                .unwrap();
        }
    });

    operators_info.past_querying_finished.notified().await;
    let sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let current_last_block = Arc::new(Mutex::new(config.current_first_block));
    let querying_thread = query_operator_socket_update(
        config.ws_endpoint.clone(),
        sockets_map.clone(),
        config.current_first_block,
        current_last_block.clone(),
        config.registry_coordinator_address,
    );

    let ruleset = config.ruleset.clone();
    let addr: SocketAddr = ([0, 0, 0, 0], 3034).into();
    let service = make_service_fn(|_| {
        let avs_registry_service = avs_registry_service.clone();
        let ws_endpoint = config.ws_endpoint.clone();
        let http_endpoint = config.http_endpoint.clone();

        let config_socket = config.socket.clone();
        let pool = pool.clone();
        let sockets_map = sockets_map.clone();
        let ruleset = ruleset.clone();
        let secret_key = config.secret_key.clone();
        let payment_phrase = config.payment_phrase.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let avs_registry_service = avs_registry_service.clone();
                let ws_endpoint = ws_endpoint.clone();
                let http_endpoint = http_endpoint.clone();

                let config_socket = config_socket.clone();
                let pool = pool.clone();

                let sockets_map = sockets_map.clone();
                let ruleset = ruleset.clone();
                let secret_key = secret_key.clone();
                let payment_phrase = payment_phrase.clone();

                async move {
                    let path = req.uri().path().to_owned();
                    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

                    match (req.method().clone(), &segments as &[&str]) {
                        (hyper::Method::POST, ["eth_address", machine_hash]) => {
                            let machine_hash = match B256::from_hex(&machine_hash) {
                                Ok(hash) => hash,
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": err.to_string()
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            };

                            let generated_address =
                                generate_eth_address(pool, machine_hash, payment_phrase).await;
                            let json_response = serde_json::json!({
                                "eth_address": generated_address
                            });
                            let json_response = serde_json::to_string(&json_response).unwrap();
                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json_response))
                                .unwrap();
                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::POST, ["issue_task", machine_hash, callback]) => {
                            let input = hyper::body::to_bytes(req.into_body())
                                .await
                                .unwrap()
                                .to_vec();
                            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);

                            let ws_provider = alloy_provider::ProviderBuilder::new()
                                .on_ws(ws_connect)
                                .await
                                .unwrap();

                            let current_block_number =
                                ws_provider.clone().get_block_number().await.unwrap();
                            let quorum_nums = [0];
                            let quorum_threshold_percentages = vec![100_u8];
                            let time_to_expiry = Duration::from_secs(10);

                            match avs_registry_service
                                .clone()
                                .get_operators_avs_state_at_block(
                                    current_block_number as u32,
                                    &quorum_nums,
                                )
                                .await
                            {
                                Ok(operators) => {
                                    let task_issued = TaskIssued {
                                        machineHash: B256::from_hex(&machine_hash).unwrap(),
                                        input: input.into(),
                                        callback: Address::parse_checksummed(callback, None)
                                            .expect("can't convert callback to Address"),
                                    };
                                    let bls_agg_response = handle_task_issued_operator(
                                        operators,
                                        true,
                                        sockets_map.clone(),
                                        config_socket.clone(),
                                        task_issued.clone(),
                                        avs_registry_service.clone(),
                                        time_to_expiry,
                                        ruleset.clone(),
                                        current_block_num,
                                        quorum_nums.to_vec(),
                                        quorum_threshold_percentages.clone(),
                                    )
                                    .await;
                                    match bls_agg_response {
                                        Ok(service_response) => {
                                            let json_responses = serde_json::json!({
                                                "service_response": service_response,
                                            });
                                            let json_responses =
                                                serde_json::to_string(&json_responses).unwrap();
                                            let response = Response::builder()
                                                .status(StatusCode::OK)
                                                .body(Body::from(json_responses))
                                                .unwrap();

                                            return Ok::<_, Infallible>(response);
                                        }
                                        Err(err) => {
                                            //handles the case when proofs weren't proved successfully
                                            let json_error = serde_json::json!({
                                                "error": err.to_string()
                                            });
                                            let json_error =
                                                serde_json::to_string(&json_error).unwrap();
                                            let response = Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Body::from(json_error))
                                                .unwrap();
                                            return Ok::<_, Infallible>(response);
                                        }
                                    }
                                }
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": format!("Failed to get operators: {:?}", err)
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            }
                        }
                        (hyper::Method::POST, ["ensure", cid_str, machine_hash, size_str]) => {
                            let generated_address = generate_eth_address(
                                pool.clone(),
                                B256::from_hex(&machine_hash).unwrap(),
                                payment_phrase,
                            )
                            .await;
                            let secret_key =
                                SecretKey::from_slice(&hex::decode(secret_key.clone()).unwrap())
                                    .unwrap();
                            let signer = PrivateKeySigner::from(secret_key);
                            let wallet = EthereumWallet::from(signer);
                            let provider = ProviderBuilder::new()
                                .with_recommended_fillers()
                                .wallet(wallet)
                                .on_http(http_endpoint.parse().unwrap());
                            let contract = IERC20::new(config.payment_token, &provider);
                            let balance_caller = contract.balanceOf(generated_address);
                            match balance_caller.call().await {
                                Ok(balance) => {
                                    println!("balanceOf {:?} = {:?}", generated_address, balance);
                                }
                                Err(err) => {
                                    println!("Transaction wasn't sent successfully: {err}");
                                }
                            }
                            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
                            let ws_provider = alloy_provider::ProviderBuilder::new()
                                .on_ws(ws_connect)
                                .await
                                .unwrap();
                            let current_block_number =
                                ws_provider.clone().get_block_number().await.unwrap();
                            let quorum_nums = [0];

                            match avs_registry_service
                                .clone()
                                .get_operators_avs_state_at_block(
                                    current_block_number as u32,
                                    &quorum_nums,
                                )
                                .await
                            {
                                Ok(operators) => {
                                    let mut states_for_operators: HashMap<String, String> =
                                        HashMap::new();
                                    for operator in operators {
                                        let operator_id = operator.1.operator_id;
                                        let sockets_map = sockets_map.lock().await;
                                        match sockets_map.get(&operator_id.to_vec()) {
                                            Some(mut socket) => {
                                                if socket == "Not Needed" {
                                                    socket = &config_socket;
                                                }

                                                let request = Request::builder()
                                                    .method("POST")
                                                    .header("X-Ruleset", &ruleset)
                                                    .uri(format!(
                                                        "{}/ensure/{}/{}/{}",
                                                        socket, cid_str, machine_hash, size_str
                                                    ))
                                                    .body(Body::empty())
                                                    .unwrap();
                                                println!(
                                                    "{}/ensure/{}/{}/{}",
                                                    socket, cid_str, machine_hash, size_str
                                                );
                                                let client = Client::new();
                                                let response =
                                                    client.request(request).await.unwrap();
                                                let response_json =
                                                    serde_json::from_slice::<serde_json::Value>(
                                                        &hyper::body::to_bytes(response)
                                                            .await
                                                            .expect(
                                                                format!(
                                                                    "Error requesting {}/ensure/{}/{}/{}",
                                                                    socket,
                                                                    cid_str,
                                                                    machine_hash,
                                                                    size_str
                                                                )
                                                                .as_str(),
                                                            )
                                                            .to_vec(),
                                                    )
                                                    .unwrap();
                                                match response_json.get("state") {
                                                    Some(serde_json::Value::String(state)) => {
                                                        states_for_operators.insert(
                                                            hex::encode(operator_id.to_vec()),
                                                            state.to_string(),
                                                        );
                                                    }
                                                    _ => {
                                                        panic!("No state found in request {}/ensure/{}/{}/{} response", socket,
                                                        cid_str,
                                                        machine_hash,
                                                        size_str);
                                                    }
                                                };
                                            }
                                            None => {
                                                let json_error = serde_json::json!({
                                                    "error": format!("No socket for operator_id = {:?}", hex::encode(operator_id.to_vec()))
                                                });
                                                let json_error =
                                                    serde_json::to_string(&json_error).unwrap();
                                                let response = Response::builder()
                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                    .body(Body::from(json_error))
                                                    .unwrap();

                                                return Ok::<_, Infallible>(response);
                                            }
                                        }
                                    }
                                    let json_responses = serde_json::json!({
                                        "operator_ids_with_states": states_for_operators,
                                    });
                                    let json_responses =
                                        serde_json::to_string(&json_responses).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(json_responses))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": format!("Failed to get operators: {:?}", err)
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            }
                        }
                        (hyper::Method::GET, ["health"]) => {
                            let json_request = r#"{"healthy": "true"}"#;
                            let response = Response::new(Body::from(json_request));
                            return Ok::<_, Infallible>(response);
                        }
                        _ => {
                            let json_error = serde_json::json!({
                                "error": "unknown request",
                            });
                            let json_error = serde_json::to_string(&json_error).unwrap();
                            let response = Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(json_error))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                    }
                }
            }))
        }
    });
    let server = Server::bind(&addr).serve(Box::new(service));
    println!("Server is listening on {}", addr);
    let _ = querying_thread.await;
    println!("Finished OperatorSocketUpdate querying");

    //Subscriber which inserts new tasks into the DB
    subscribe_task_issued(
        config.ws_endpoint.clone(),
        config.http_endpoint.clone(),
        config.payment_token.clone(),
        config.task_issuer.clone(),
        pool.clone(),
        config.secret_key.clone(),
        config.payment_phrase.clone(),

    );
    //Subscriber which handles new tasks received from L2
    subscribe_task_issued_l2(
        config.l2_ws_endpoint.clone(),
        config.l2_coprocessor_address,
        pool.clone(),
    );

    //update the handler to process task from l2
    new_task_issued_handler_l2(
        config.clone(),
        l1_coprocessor.clone(),
        cross_domain_messenger.clone(),
        pool.clone(),
    );

    //subscribe to taskcompleted event on l2
    subscribe_task_completed_l2(
        config.l2_ws_endpoint.clone(),
        config.l2_coprocessor_address,
        pool.clone(),
        config.clone(),
    );

    //Subscriber which handles new tasks received from DB
    new_task_issued_handler(
        config.ws_endpoint.clone(),
        config.http_endpoint.clone(),
        avs_registry_service.clone(),
        sockets_map.clone(),
        config.socket.clone(),
        config.ruleset,
        current_block_num,
        config.secret_key.clone(),
        config.task_issuer,
        pool.clone(),
        config.postgre_connect_request,
    );
    subscribe_operator_socket_update(
        arc_ws_endpoint,
        sockets_map.clone(),
        config.registry_coordinator_address,
        current_last_block.clone(),
    );
    server.await.unwrap();
}

//fn to subscribe to task issued event on l2
fn subscribe_task_issued_l2(
    l2_ws_provider: Provider,
    l2_coprocessor: L2Coprocessor<Provider>,
    pool: Pool<PostgresConnectionManager<NoTls>>,
) {
    task::spawn(async move {
        let mut event_stream = l2_coprocessor
            .event::<TaskIssuedEvent>()
            .from_block(0)
            .stream()
            .await
            .unwrap();

        while let Some(event) = event_stream.next().await {
            match event {
                Ok(task_issued_event) => {
                    println!("New TaskIssued event on L2: {:?}", task_issued_event);

                    let client = pool.get().await.unwrap();
                    match client.execute(
                        "INSERT INTO issued_tasks (machine_hash, input, callback, task_type, status) VALUES ($1, $2, $3, $4, $5::task_status)",
                        &[
                            &task_issued_event.machine_hash.0.to_vec(),
                            &task_issued_event.input.to_vec(),
                            &task_issued_event.callback.0.to_vec(),
                            &task_issued_event.task_type,
                            &TaskStatus::WaitsForHandling,
                        ],
                    ).await {
                        Ok(_) => {
                            println!("Inserted new task into the database.");
                        }
                        Err(err) => {
                            eprintln!("Error inserting task into database: {:?}", err);
                        }
                    };
                },
                Err(err) => {
                    eprintln!("Error receiving TaskIssued event on L2: {:?}", err);
                }
            }
        }
    });
}

fn query_operator_socket_update(
    ws_endpoint: String,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    current_first_block: u64,
    current_last_block: Arc<Mutex<u64>>,
    registry_coordinator_address: Address,
) -> JoinHandle<()> {
    task::spawn({
        let sockets_map = Arc::clone(&sockets_map);
        let current_last_block = Arc::clone(&current_last_block);
        async move {
            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();

            let last_block = ws_provider.clone().get_block_number().await.unwrap();
            let mut current_last_block = current_last_block.lock().await;
            let mut current_first_block = current_first_block;

            while current_first_block <= last_block {
                *current_last_block = if current_first_block + 10000 < last_block {
                    current_first_block + 10000
                } else {
                    last_block
                };

                let event_filter = Filter::new()
                    .address(registry_coordinator_address)
                    .from_block(current_first_block.clone())
                    .to_block(current_last_block.clone())
                    .event("OperatorSocketUpdate(bytes32,string)");

                let event: Event<_, _, ISocketUpdater::OperatorSocketUpdate, _> =
                    Event::new(ws_provider.clone(), event_filter);
                let filtered_events = event.query().await.unwrap();

                for (operator_socket_update, log) in filtered_events {
                    println!(
                        "stream_event operator socket update {:?}",
                        operator_socket_update
                    );
                    println!("stream_event operator socket update log {:?}", log);
                    sockets_map.lock().await.insert(
                        operator_socket_update.operatorId.as_slice().to_vec(),
                        operator_socket_update.socket,
                    );
                }
                if current_first_block == *current_last_block {
                    break;
                }
                current_first_block = current_last_block.clone() + 1;
            }
        }
    })
}

async fn handle_task_issued_operator(
    operators: HashMap<FixedBytes<32>, OperatorAvsState>,
    generate_proofs: bool,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    config_socket: String,
    stream_event: TaskIssued,
    avs_registry_service: AvsRegistryServiceChainCaller<
        AvsRegistryChainReader,
        OperatorInfoServiceInMemory,
    >,
    time_to_expiry: Duration,
    ruleset: String,
    current_block_num: u64,
    quorum_nums: Vec<u8>,
    quorum_threshold_percentages: Vec<u8>,
) -> Result<
    (
        BlsAggregationServiceResponse,
        HashMap<alloy_primitives::FixedBytes<32>, Vec<(u16, Vec<u8>)>>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut bls_agg_service = BlsAggregatorService::new(avs_registry_service.clone());
    let mut response_digest_map = HashMap::new();
    for operator in operators {
        bls_agg_service = BlsAggregatorService::new(avs_registry_service.clone());
        let operator_id = operator.1.operator_id;
        let sockets_map = sockets_map.lock().await;
        match sockets_map.get(&operator_id.to_vec()) {
            Some(mut socket) => {
                if socket == "Not Needed" {
                    socket = &config_socket;
                }

                let request = Request::builder()
                    .method("POST")
                    .header("X-Ruleset", &ruleset)
                    .uri(format!("{}/classic/{:x}", socket, stream_event.machineHash))
                    .body(Body::from(stream_event.input.to_vec()))
                    .unwrap();
                println!("{}/classic/{:x}", socket, stream_event.machineHash);
                let client = Client::new();
                let response = client.request(request).await.unwrap();
                let response_json = serde_json::from_slice::<serde_json::Value>(
                    &hyper::body::to_bytes(response)
                        .await
                        .expect(
                            format!(
                                "No respose for {}/classic/{:x}",
                                socket, stream_event.machineHash,
                            )
                            .as_str(),
                        )
                        .to_vec(),
                )
                .unwrap();

                let response_signature: String = match response_json.get("signature") {
                    Some(serde_json::Value::String(sign)) => sign.to_string(),
                    _ => {
                        panic!("No signature found in request response");
                    }
                };

                let finish_callback: Vec<serde_json::Value> =
                    match response_json.get("finish_callback") {
                        Some(serde_json::Value::Array(finish_callback)) => {
                            if finish_callback.len() == 2
                                && finish_callback[0].is_number()
                                && finish_callback[1].is_array()
                            {
                                finish_callback[1].as_array().unwrap().to_vec()
                            } else {
                                finish_callback.to_vec()
                            }
                        }
                        _ => {
                            panic!("No finish_callback found in request response");
                        }
                    };
                let finish_result = extract_number_array(finish_callback);
                let outputs_vector: Vec<(u16, Vec<u8>)> =
                    match response_json.get("outputs_callback_vector") {
                        Some(outputs_callback) => {
                            serde_json::from_value(outputs_callback.clone()).unwrap()
                        }
                        _ => {
                            panic!("No outputs_callback_vector found in request response");
                        }
                    };
                if generate_proofs {
                    let mut keccak_outputs = Vec::new();

                    for output in outputs_vector.clone() {
                        let mut hasher = Keccak256::new();
                        hasher.update(output.1.clone());
                        keccak_outputs.push(hasher.finalize());
                    }

                    let proofs = outputs_merkle::create_proofs(keccak_outputs, HEIGHT).unwrap();

                    if proofs.0.to_vec() != finish_result {
                        return Err(format!("Outputs weren't proven successfully").into());
                    }
                }

                let signature_bytes = hex::decode(&response_signature).unwrap();
                println!("signature_bytes {:?}", signature_bytes);
                let g1: ark_bn254::g1::G1Affine =
                    ark_bn254::g1::G1Affine::deserialize_uncompressed(&signature_bytes[..])
                        .unwrap();

                let mut task_response_buffer = vec![0u8; 12];
                task_response_buffer.extend_from_slice(&hex::decode(&ruleset).unwrap());
                task_response_buffer.extend_from_slice(&stream_event.machineHash.to_vec());

                let mut hasher = Keccak256::new();
                hasher.update(&stream_event.input.clone());
                let payload_keccak = hasher.finalize();

                task_response_buffer.extend_from_slice(&payload_keccak.to_vec());
                task_response_buffer.extend_from_slice(&finish_result);

                let task_response_digest = keccak256(&task_response_buffer);

                bls_agg_service
                    .initialize_new_task(
                        TASK_INDEX,
                        current_block_num as u32,
                        quorum_nums.clone(),
                        quorum_threshold_percentages.clone(),
                        time_to_expiry,
                    )
                    .await
                    .unwrap();

                bls_agg_service
                    .process_new_signature(
                        TASK_INDEX,
                        task_response_digest,
                        Signature::new(g1),
                        operator_id.into(),
                    )
                    .await
                    .unwrap();

                response_digest_map.insert(
                    B256::from_slice(task_response_digest.as_slice()),
                    outputs_vector.clone(),
                );
            }
            None => {
                eprint!("No socket for operator_id {:?}", hex::encode(operator_id));
            }
        }
    }
    let bls_agg_response = bls_agg_service
        .aggregated_response_receiver
        .lock()
        .await
        .recv()
        .await
        .unwrap()
        .unwrap();
    println!(
        "agg_response_to_non_signer_stakes_and_signature {:?}",
        bls_agg_response
    );
    Ok((bls_agg_response, response_digest_map))
}
fn extract_number_array(values: Vec<serde_json::Value>) -> Vec<u8> {
    let mut byte_vec = Vec::new();

    for value in values {
        match value {
            serde_json::Value::Number(num) => {
                byte_vec.push(num.as_u64().unwrap() as u8);
            }
            _ => {}
        }
    }

    byte_vec
}

fn new_task_issued_handler(
    ws_endpoint: String,
    http_endpoint: String,
    avs_registry_service: AvsRegistryServiceChainCaller<
        AvsRegistryChainReader,
        OperatorInfoServiceInMemory,
    >,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    config_socket: String,
    ruleset: String,
    current_block_num: u64,
    secret_key: String,
    task_issuer: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    postgre_connect_request: String,
) {
    task::spawn({
        async move {
            let client = pool.get().await.unwrap();
            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();
            let quorum_nums = [0];
            let quorum_threshold_percentages = vec![100_u8];
            let time_to_expiry = Duration::from_secs(10);

            let (notification_client, mut connection) =
                tokio_postgres::connect(&postgre_connect_request, NoTls)
                    .await
                    .unwrap();
            let (tx, rx) = futures_channel::mpsc::unbounded();
            let stream =
                stream::poll_fn(move |cx| connection.poll_message(cx)).map_err(|e| panic!("{}", e));
            let connection = stream.forward(tx).map(|r| r.unwrap());
            tokio::spawn(connection);
            let mut notification_filter = rx.filter_map(|m| match m {
                AsyncMessage::Notification(n) => futures_util::future::ready(Some(n)),
                _ => futures_util::future::ready(None),
            });

            loop {
                match client
                    .query_one(
                        "UPDATE issued_tasks SET status = $1 WHERE id = ( SELECT id FROM issued_tasks WHERE status = $2 ORDER BY id LIMIT 1) RETURNING *;",
                        &[&task_status::in_progress, &task_status::waits_for_handling],
                    )
                    .await
                {
                    Ok(row) => {
                        let id: i32 = row.get(0);
                        let machine_hash: Vec<u8> = row.get(1);
                        let input: Vec<u8> = row.get(2);
                        let callback: Vec<u8> = row.get(3);

                        let task_issued = TaskIssued {
                            machineHash: B256::from_slice(&machine_hash),
                            input: input.into(),
                            callback: Address::from_slice(&callback),
                        };
                        let current_block_number =
                            ws_provider.clone().get_block_number().await.unwrap();
                        match avs_registry_service
                            .clone()
                            .get_operators_avs_state_at_block(
                                current_block_number as u32,
                                &quorum_nums,
                            )
                            .await
                        {
                            Ok(operators) => {
                                let bls_agg_response = handle_task_issued_operator(
                                    operators,
                                    false,
                                    sockets_map.clone(),
                                    config_socket.clone(),
                                    task_issued.clone(),
                                    avs_registry_service.clone(),
                                    time_to_expiry,
                                    ruleset.clone(),
                                    current_block_num,
                                    quorum_nums.to_vec(),
                                    quorum_threshold_percentages.clone(),
                                )
                                .await
                                .unwrap();
                                let secret_key = SecretKey::from_slice(
                                    &hex::decode(secret_key.clone()).unwrap(),
                                )
                                .unwrap();
                                let signer = PrivateKeySigner::from(secret_key);
                                let wallet = EthereumWallet::from(signer);
                                let provider = ProviderBuilder::new()
                                    .with_recommended_fillers()
                                    .wallet(wallet)
                                    .on_http(http_endpoint.parse().unwrap());
                                let contract =
                                    ResponseCallbackContract::new(task_issuer, &provider);
                                let non_signer_stakes_and_signature_response =
                                    agg_response_to_non_signer_stakes_and_signature(
                                        bls_agg_response.0.clone(),
                                    );
                                let outputs: Vec<alloy_primitives::Bytes> = bls_agg_response
                                    .1
                                    .get(&bls_agg_response.0.task_response_digest)
                                    .unwrap()
                                    .iter()
                                    .map(|bytes| bytes.clone().1.into())
                                    .collect();
                                let call_builder = contract.solverCallbackOutputsOnly(
                                    ResponseSol {
                                        ruleSet: Address::parse_checksummed(
                                            format!("0x{}", ruleset.clone()),
                                            None,
                                        )
                                        .unwrap(),
                                        machineHash: task_issued.machineHash,
                                        payloadHash: keccak256(&task_issued.input),
                                        outputMerkle: outputs_merkle::create_proofs(
                                            outputs
                                                .iter()
                                                .map(|element| keccak256(&element.0))
                                                .collect(),
                                            HEIGHT,
                                        )
                                        .unwrap()
                                        .0,
                                    },
                                    quorum_nums.into(),
                                    100,
                                    100,
                                    current_block_num as u32,
                                    non_signer_stakes_and_signature_response.clone().into(),
                                    task_issued.callback,
                                    outputs,
                                );
                                let root_provider = get_provider(http_endpoint.as_str());
                                let service_manager =
                                    IBLSSignatureChecker::new(task_issuer, root_provider);
                                let check_signatures_result = service_manager
                                    .checkSignatures(
                                        bls_agg_response.0.task_response_digest,
                                        alloy_primitives::Bytes::from(quorum_nums),
                                        current_block_num as u32,
                                        non_signer_stakes_and_signature_response,
                                    )
                                    .call()
                                    .await
                                    .unwrap();
                                println!(
                                    "check_signatures_result {:?} {:?} {:?}",
                                    check_signatures_result._0.signedStakeForQuorum,
                                    check_signatures_result._0.totalStakeForQuorum,
                                    check_signatures_result._1
                                );
                                match call_builder.send().await {
                                    Ok(_pending_tx) => {}
                                    Err(err) => {
                                        println!("Transaction wasn't sent successfully: {err}");
                                    }
                                }

                                //Update status after task was handled
                                client
                                    .execute(
                                        "UPDATE issued_tasks SET status = $1 WHERE id = $2;",
                                        &[&task_status::handled, &id],
                                    )
                                    .await
                                    .unwrap();
                            }
                            Err(e) => println!(
                                "no operators found at block {:?}. Error {:?}",
                                current_block_number, e
                            ),
                        }
                    }
                    Err(_) => {
                        println!("waiting for new notifications");
                        notification_client
                            .batch_execute("LISTEN new_task_issued;")
                            .await
                            .unwrap();
                        notification_filter.next().await;
                    }
                }
            }
        }
    });
}

async fn process_type_a_task(machine_hash: &[u8], input: &[u8], config: &Config) -> (L2Response, Vec<Vec<u8>>) {
    let output = input.iter().cloned().rev().collect::<Vec<u8>>();
    let outputs = vec![output];
    let response = compute_response(machine_hash, input, config, &outputs);
    (response, outputs)
}

async fn process_type_b_task(machine_hash: &[u8], input: &[u8], config: &Config) -> (L2Response, Vec<Vec<u8>>) {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let output = hasher.finalize().to_vec();
    let outputs = vec![output];
    let response = compute_response(machine_hash, input, config, &outputs);
    (response, outputs)
}

fn compute_response(machine_hash: &[u8], input: &[u8], config: &Config, outputs: &[Vec<u8>]) -> L2Response {
    let output_merkle = compute_output_merkle(outputs);
    L2Response {
        rule_set: Address::parse_checksummed(&config.ruleset, None).unwrap(),
        machine_hash: B256::from_slice(machine_hash),
        payload_hash: keccak256(input),
        output_merkle,
    }
}

fn compute_output_merkle(outputs: &[Vec<u8>]) -> B256 {
    if outputs.is_empty() {
        return B256::zero();
    }
    let leaves: Vec<B256> = outputs.iter().map(|output| keccak256(output)).collect();
    merkle_root(&leaves)
}
fn merkle_root(leaves: &[B256]) -> B256 {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut next_level = vec![];
    for i in (0..leaves.len()).step_by(2) {
        let left = leaves[i];
        let right = if i + 1 < leaves.len() { leaves[i + 1] } else { leaves[i] };
        let combined = [left.0.as_ref(), right.0.as_ref()].concat();
        next_level.push(keccak256(&combined));
    }
    merkle_root(&next_level)
}

fn abi_encode_response(response: &L2Response) -> Vec<u8> {
    use alloy_sol_types::SolType;

    let response_tuple = (
        response.rule_set,
        response.machine_hash,
        response.payload_hash,
        response.output_merkle,
    );
    let encoded = <(Address, B256, B256, B256) as SolType>::encode(&response_tuple);
    encoded
}

async fn store_outputs_for_task(machine_hash: &[u8], outputs: &[Vec<u8>]) {
    let mut path = PathBuf::from("outputs");
    fs::create_dir_all(&path).unwrap();
    path.push(hex::encode(machine_hash));

    let serialized_outputs = serde_json::to_vec(outputs).unwrap();
    fs::write(path, serialized_outputs).unwrap();
}
async fn retrieve_outputs_for_task(machine_hash: &[u8]) -> Vec<Vec<u8>> {
    let mut path = PathBuf::from("outputs");
    path.push(hex::encode(machine_hash));

    if let Ok(data) = fs::read(path) {
        serde_json::from_slice(&data).unwrap()
    } else {
        vec![]
    }
}

fn subscribe_task_completed_l2(
    l2_ws_endpoint: String,
    l2_coprocessor_address: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    config: Config,
) {
    task::spawn({
        async move {
            println!("Started TaskCompleted subscription on L2");
            let ws_connect = alloy_provider::WsConnect::new(l2_ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();

            let event_filter = Filter::new()
                .address(l2_coprocessor_address)
                .event("TaskCompleted(bytes32)");

            let event: Event<_, _, L2CoprocessorEvents::TaskCompleted, _> =
                Event::new(ws_provider.clone(), event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();

            while let Ok((stream_event, _)) = stream.next().await.unwrap() {
                println!("TaskCompleted event on L2: {:?}", stream_event);
                handle_task_completed_l2(stream_event, &pool, &config).await;
            }
        }
    });
}

async fn handle_task_completed_l2(
    task_completed_event: L2CoprocessorEvents::TaskCompleted,
    pool: &Pool<PostgresConnectionManager<NoTls>>,
    config: &Config,
) {
    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT machineHash, input, callback FROM issued_tasks WHERE responseHash = $1",
            &[&task_completed_event.responseHash.0.to_vec()],
        )
        .await
        .unwrap();

    if !rows.is_empty() {
        let machine_hash: Vec<u8> = rows[0].get(0);
        let input: Vec<u8> = rows[0].get(1);
        let callback: Vec<u8> = rows[0].get(2);

        let response = ResponseSol {
            ruleSet: Address::parse_checksummed(&config.ruleset, None).unwrap(),
            machineHash: B256::from_slice(&machine_hash),
            payloadHash: keccak256(&input),
            outputMerkle: compute_output_merkle(&input),
        };

        let outputs: Vec<alloy_primitives::Bytes> = retrieve_outputs_for_task(&machine_hash).await;

        let l2_provider = ProviderBuilder::new()
            .on_http(config.l2_http_endpoint.parse().unwrap());
        let l2_coprocessor = L2Coprocessor::new(config.l2_coprocessor_address, &l2_provider);

        l2_coprocessor
            .callbackWithOutputs(response, outputs, Address::from_slice(&callback))
            .send()
            .await
            .unwrap();

        println!("Successfully called callbackWithOutputs on L2");
    }
}
fn subscribe_task_issued(
    ws_endpoint: String,
    http_endpoint: String,
    payment_token: Address,
    task_issuer: Address,
    l2_coprocessor_address: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    secret_key: String,
    payment_phrase: String
) {
    task::spawn({
        async move {
            let client = pool.get().await.unwrap();
            println!("Started TaskIssued subscription");
            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();
            let event_filter = Filter::new().address(l2_coprocessor_address);
            let event: Event<_, _, IL2Coprocessor::TaskIssued, _> =
                Event::new(ws_provider.clone(), event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();
            while let Ok((stream_event, _)) = stream.next().await.unwrap() {
                println!("new TaskIssued {:?}", stream_event);
                let generated_address = generate_eth_address(
                    pool.clone(),
                    stream_event.machineHash,
                    payment_phrase.clone(),
                )
                .await;
                let secret_key =
                    SecretKey::from_slice(&hex::decode(secret_key.clone()).unwrap()).unwrap();
                let signer = PrivateKeySigner::from(secret_key);
                let wallet = EthereumWallet::from(signer);
                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(wallet)
                    .on_http(http_endpoint.parse().unwrap());
                let contract = IERC20::new(payment_token, &provider);
                let balance_caller = contract.balanceOf(generated_address);
                match balance_caller.call().await {
                    Ok(balance) => {
                        println!("balanceOf {:?} = {:?}", generated_address, balance);
                    }
                    Err(err) => {
                        println!("Transaction wasn't sent successfully: {err}");
                    }
                }
                match client.execute(
                    "INSERT INTO issued_tasks (machineHash, input, callback, status) VALUES ($1, $2, $3, $4::task_status)",
                    &[
                        &stream_event.machineHash.0.to_vec(),
                        &stream_event.input.to_vec(),
                        &stream_event.callback.to_vec(),
                        &task_status::waits_for_handling
                    ],
                ).await {
                    Ok(_) => {
                    client
                    .batch_execute(
                        "
                        NOTIFY new_task_issued;",
                    )
                    .await.unwrap();
                },
                    Err(_) => {
                    }
                };
            }
        }
    });
}

fn subscribe_task_completed(
    ws_endpoint: String,
    l2_coprocessor_address: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
) {
    task::spawn({
        async move {
            println!("Started TaskCompleted subscription");
            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();

            let event_filter = Filter::new().address(l2_coprocessor_address);
            let event: Event<_, _, L2Coprocessor::TaskCompleted, _> =
                Event::new(ws_provider.clone(), event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();

            while let Some(Ok((task_completed_event, _))) = stream.next().await {
                println!("TaskCompleted event: {:?}", task_completed_event);

                //handle task completion
                handle_task_completed(
                    task_completed_event,
                    &pool,
                    &config
                )
                .await;
            }
        }
    });
}

async fn handle_task_completed(
    task_completed_event: L2Coprocessor::TaskCompleted,
    pool: &Pool<PostgresConnectionManager<NoTls>>,
    config: &Config,
) {
    let client = pool.get().await.unwrap();

    // Retrieve task information from the database
    let rows = client
        .query(
            "SELECT machine_hash, input, callback FROM issued_tasks WHERE response_hash = $1",
            &[&task_completed_event.response_hash.0.to_vec()],
        )
        .await
        .unwrap();

    if !rows.is_empty() {
        let machine_hash: Vec<u8> = rows[0].get(0);
        let input: Vec<u8> = rows[0].get(1);
        let callback: Vec<u8> = rows[0].get(2);

        // Prepare the response
        let response = L2Response {
            rule_set: Address::parse_checksummed(&config.ruleset, None).unwrap(),
            machine_hash: B256::from_slice(&machine_hash),
            payload_hash: keccak256(&input),
            output_merkle: compute_output_merkle(&input),
        };

        // Retrieve outputs from processing
        let outputs: Vec<Vec<u8>> = get_outputs_for_task(&machine_hash).await;

        // Create an instance of the L2 Coprocessor contract
        let l2_provider = ProviderBuilder::new().on_http(config.l2_http_endpoint.parse().unwrap());
        let l2_coprocessor = L2Coprocessor::new(config.l2_coprocessor_address, &l2_provider);

        // Call callbackWithOutputs on L2 Coprocessor
        match l2_coprocessor
            .callback_with_outputs(
                response,
                outputs,
                Address::from_slice(&callback),
            )
            .send()
            .await
        {
            Ok(_) => {
                println!("Successfully called callbackWithOutputs");
            }
            Err(err) => {
                eprintln!("Error calling callbackWithOutputs: {:?}", err);
            }
        }
    }
}

fn subscribe_operator_socket_update(
    arc_ws_endpoint: Arc<String>,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    registry_coordinator_address: Address,
    current_last_block: Arc<Mutex<u64>>,
) {
    task::spawn({
        println!("Started OperatorSocketUpdate subscription");

        let ws_endpoint = Arc::clone(&arc_ws_endpoint);
        let sockets_map = Arc::clone(&sockets_map);

        async move {
            let ws_connect = alloy_provider::WsConnect::new((*ws_endpoint).clone());
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();
            let event_filter = Filter::new()
                .address(registry_coordinator_address)
                .event("OperatorSocketUpdate(bytes32,string)")
                .from_block(*current_last_block.lock().await);

            let event: Event<_, _, ISocketUpdater::OperatorSocketUpdate, _> =
                Event::new(ws_provider, event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();
            while let Ok((stream_event, _)) = stream.next().await.unwrap() {
                sockets_map.lock().await.insert(
                    stream_event.operatorId.as_slice().to_vec(),
                    stream_event.socket,
                );
            }
        }
    });
}

async fn generate_eth_address(
    pool: Pool<PostgresConnectionManager<NoTls>>,
    machine_hash: FixedBytes<32>,
    payment_phrase: String,
) -> Address {
    let client = pool.get().await.unwrap();
    let _ = client
        .execute(
            "INSERT INTO machine_hashes (machine_hash) VALUES ($1)",
            &[&machine_hash.to_vec()],
        )
        .await;
    let address_index = client
        .query_one(
            "SELECT id FROM machine_hashes WHERE machine_hash = $1 ",
            &[&machine_hash.to_vec()],
        )
        .await
        .unwrap();

    let index: i32 = address_index.get(0);

    let builder = MnemonicBuilder::<coins_bip39::wordlist::english::English>::default()
        .index(index as u32)
        .unwrap()
        .phrase(payment_phrase)
        .build()
        .unwrap();
    builder.address()
}

impl Into<NonSignerStakesAndSignatureSol> for NonSignerStakesAndSignature {
    fn into(self) -> NonSignerStakesAndSignatureSol {
        let apk_g2 = G2PointSol {
            X: self.apkG2.X,
            Y: self.apkG2.Y,
        };
        let sigma = G1PointSol {
            X: self.sigma.X,
            Y: self.sigma.Y,
        };
        NonSignerStakesAndSignatureSol {
            nonSignerPubkeys: self
                .nonSignerPubkeys
                .iter()
                .map(|g1_point| G1PointSol {
                    X: g1_point.X,
                    Y: g1_point.Y,
                })
                .collect(),
            quorumApks: self
                .quorumApks
                .iter()
                .map(|g1_point| G1PointSol {
                    X: g1_point.X,
                    Y: g1_point.Y,
                })
                .collect(),
            apkG2: apk_g2,
            sigma,
            nonSignerQuorumBitmapIndices: self.nonSignerQuorumBitmapIndices,
            quorumApkIndices: self.quorumApkIndices,
            totalStakeIndices: self.totalStakeIndices,
            nonSignerStakeIndices: self.nonSignerStakeIndices,
        }
    }
}

fn agg_response_to_non_signer_stakes_and_signature(
    agg_response: BlsAggregationServiceResponse,
) -> NonSignerStakesAndSignature {
    let non_signer_pubkeys: Vec<G1Point> = agg_response
        .non_signers_pub_keys_g1
        .iter()
        .map(|point| convert_to_bls_checker_g1_point(point.g1()).unwrap())
        .collect();
    let quorum_apks = agg_response
        .quorum_apks_g1
        .iter()
        .map(|point| convert_to_bls_checker_g1_point(point.g1()).unwrap())
        .collect();

    NonSignerStakesAndSignature {
        nonSignerPubkeys: non_signer_pubkeys,
        quorumApks: quorum_apks,
        apkG2: convert_to_bls_checker_g2_point(agg_response.signers_apk_g2.g2()).unwrap(),
        sigma: convert_to_bls_checker_g1_point(agg_response.signers_agg_sig_g1.g1_point().g1())
            .unwrap(),
        nonSignerQuorumBitmapIndices: agg_response.non_signer_quorum_bitmap_indices,
        quorumApkIndices: agg_response.quorum_apk_indices,
        totalStakeIndices: agg_response.total_stake_indices,
        nonSignerStakeIndices: agg_response.non_signer_stake_indices,
    }
}
sol!(
   interface ICoprocessor {
        #[derive(Debug)]
        event TaskIssued(bytes32 machineHash, bytes input, address callback);
   }
);

sol!(
    #[sol(rpc)]
    contract IERC20 {
        constructor(address) {}

        #[derive(Debug)]
        function balanceOf(address account) external view returns (uint256);
    }
);

sol!(
    interface ISocketUpdater {
        // EVENTS
        #[derive(Debug)]
        event OperatorSocketUpdate(bytes32 indexed operatorId, string socket);
    }
);
sol! {
    #[derive(Debug, Default)]
    struct ResponseSol {
        address ruleSet;
        bytes32 machineHash;
        bytes32 payloadHash;
        bytes32 outputMerkle;
    }
    #[derive(Debug)]
        struct G1PointSol {
            uint256 X;
            uint256 Y;
        }
        #[derive(Debug)]
        struct G2PointSol {
            uint256[2] X;
            uint256[2] Y;
        }
    #[derive(Debug)]
    struct NonSignerStakesAndSignatureSol {
        uint32[] nonSignerQuorumBitmapIndices;
        G1PointSol[] nonSignerPubkeys;
        G1PointSol[] quorumApks;
        G2PointSol apkG2;
        G1PointSol sigma;
        uint32[] quorumApkIndices;
        uint32[] totalStakeIndices;
        uint32[][] nonSignerStakeIndices;
     }
    #[sol(rpc)]
    contract ResponseCallbackContract {
        constructor(address) {}

        #[derive(Debug)]
        function solverCallbackOutputsOnly(
            ResponseSol calldata resp,
            bytes calldata quorumNumbers,
            uint32 quorumThresholdPercentage,
            uint8 thresholdDenominator,
            uint32 blockNumber,
            NonSignerStakesAndSignatureSol memory nonSignerStakesAndSignature,
            address callback_address,
            bytes[] calldata outputs
        );
    }
}

sol!(
    interface IL2Coprocessor {
        #[derive(Debug)]
        event TaskIssued(bytes32 machineHash, bytes input, address callback);
        #[derive(Debug)]
        event TaskCompleted(bytes32 indexed machineHash, bytes32 responseHash);

        function issueTask(bytes32 machineHash, bytes calldata input, address callback) external;
        function storeResponseHash(bytes32 responseHash) external;
        function callbackWithOutputs(
            Response calldata resp,
            bytes[] calldata outputs,
            address callbackAddress
        ) external;
    }

    #[derive(Debug, Default)]
    struct Response {
        address ruleSet;
        bytes32 machineHash;
        bytes32 payloadHash;
        bytes32 outputMerkle;
    }
);

