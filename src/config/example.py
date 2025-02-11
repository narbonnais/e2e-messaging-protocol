from .client_config_service import ClientConfigService
from .server_config_service import ServerConfigService


def main():
    client_config = ClientConfigService()  # or specify an alternate path if needed
    server_conf = client_config.get_server_config()
    web_conf = client_config.get_web_config()
    data_dir = client_config.get_data_dir()
    db_conf = client_config.get_database_config()

    print("--------------------------------")
    print("Client Server Config:", server_conf)
    print("Client Web Config:", web_conf)
    print("Data Directory:", data_dir)
    print("Client Database Config:", db_conf)

    server_config = ServerConfigService()  # or specify an alternate path if needed
    tcp_conf = server_config.get_tcp_server_config()
    web_conf = server_config.get_web_server_config()
    db_conf = server_config.get_database_config()

    print("--------------------------------")
    print("TCP Server Config:", tcp_conf)
    print("Web Server Config:", web_conf)
    print("Server Database Config:", db_conf)


if __name__ == "__main__":
    main()
