#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_DEFAULT_PATH "config/honeytrap.conf"
#define CFG_STR_LEN 256

struct config {
    int  honeypot_port;
    int  honeypot_login_after;
    int  honeypot_max_clients;

    char ids_interface[CFG_STR_LEN];
    char ids_pcap_file[CFG_STR_LEN];
    int  ids_portscan_ports;
    int  ids_portscan_window_sec;
    int  ids_synflood_syns;
    int  ids_synflood_window_sec;

    int  core_queue_capacity;
    char storage_db_path[CFG_STR_LEN];
    char storage_report_path[CFG_STR_LEN];
};

void config_set_defaults(struct config *cfg);

int config_load(const char *path, struct config *cfg);

#endif
