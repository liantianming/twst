import os
import json
import time
import socket

import requests
import logging
import stat

pg_cmd_path = "/usr/lib/postgresql/scripts/"


def get_wvip():
    return requests.get("http://metadata/self/cluster/endpoints/reserved_ips/vip/value").text


def exec_cmd(cmd, *ip):
    if (len(ip) != 0) and ip[0] != get_self_ip():
        cmd = "ssh -T -i /usr/lib/postgresql/ssh-privatekey root@" + ip[0] + " " + pg_cmd_path + "/pgmanager.py " + cmd
        logging.debug("exec cmd:[%s] on ip:[%s]," % (cmd, ip[0]))
    else:
        logging.debug("exec cmd:[%s]locally" % cmd)
    p = os.popen(cmd)
    result = (p.read()).strip()
    return result 


def get_pg_version():
    if os.path.exists("/data/pgsql/main/PG_VERSION"):
        with open("/data/pgsql/main/PG_VERSION", "r") as f:
            return f.read().strip()
    return requests.get("http://metadata/self/env/pg_version").text


def get_self_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


pg_version = get_pg_version()
pg_bin_path = "/usr/lib/postgresql/%s/bin/" % pg_version 
pg_cfg_path = "/etc/postgresql/%s/main" % pg_version
pg_password = "QY3.14coolpg"
template_data_path = "/var/lib/postgresql/%s/main" % pg_version
pg_data_path = "/data/pgsql/main/"
mgr_log_path = "/data/mgrlog/"
if not os.path.exists(mgr_log_path):
    os.mkdir(mgr_log_path)
    exec_cmd("chmod -R 644 " + mgr_log_path)
pg_log_path = "/data/pglog/"
if not os.path.exists(pg_log_path):
    os.mkdir(pg_log_path)
    exec_cmd("chmod -R 777 " + pg_log_path)
recovery_conf_content = """standby_mode = 'on'
primary_conninfo = 'user=replica password=%s host=%s port=5432 application_name=%s sslmode=prefer sslcompression=1 krbsrvname=postgres'
recovery_target_timeline = 'latest'
trigger_file = '/tmp/pg_trigger'""" % (pg_password, get_wvip(), get_self_ip().split('.')[-1])
ignore_agent_path = "/usr/local/etc/ignore_agent"
pg_port = "5432"
keepalived_conf = "/etc/keepalived/keepalived.conf"
lvs_wait_timeout = "3600"
need_restart_param_list = ["max_connections", "wal_buffers", "max_prepared_transactions", "max_wal_senders", "shared_preload_libraries", "wal_level", "shared_buffers"]
need_restart_pool_param_list = ["max_pool"]
logging.basicConfig(filename=mgr_log_path+ "/pgmanager.log", level=logging.INFO, format='%(levelname)s:%(asctime)s:%(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)


def get_pg_ip_list():
    get_ip_cmd = "curl -s http://metadata/self/hosts/pg/ | grep /ip | awk -F' ' {'print $2}'| sed 's/ //g'| sort"
    ip_list = exec_cmd(get_ip_cmd).splitlines()
    return ip_list


def get_ri_ip_list():
    get_ip_cmd = "curl -s http://metadata/self/hosts/ri/ | grep /ip | awk -F' ' {'print $2}'| sed 's/ //g'| sort"
    ip_list = exec_cmd(get_ip_cmd).splitlines()
    return ip_list


def get_scaled_iplist():
    ip_list = get_pg_ip_list() + get_ri_ip_list()
    ip_list = ip_list + get_added_ip_list()
    ip_list = list(set(ip_list) - set(get_deleted_ip_list()))
    logging.info("scaled ip list:[%s]" % ip_list)
    return ip_list


def get_self_role():
    if check_pg_ok(get_self_ip()):
        return get_role_by_sql(get_self_ip())
    elif os.path.exists(pg_data_path + "recovery.conf"):
        return "standby"
    elif os.path.exists(pg_data_path + "recovery.done"):
        return "primary"
    else:
        if get_pg_ip_list()[0] == get_self_ip():
            return "primary"
        else:
            return "standby"


def auto_failover():
    return requests.get("http://metadata/self/env/auto_failover").text == "Yes"


def get_rvip():
    return requests.get("http://metadata/self/cluster/endpoints/reserved_ips/rvip/value").text


def get_other_ip_list():
    self_ip = get_self_ip()
    ip_list = get_pg_ip_list() + get_ri_ip_list()
    index = ip_list.index(self_ip)
    return ip_list[index + 1:] + ip_list[:index]


def get_receive_lsn(ip):
    get_receive_lsn_cmd = pg_bin_path + "psql -U postgres -h" + ip + " password=" + pg_password
    if pg_version == "9.6":
        get_receive_lsn_cmd += " -t -c  'select pg_last_xlog_receive_location(); '"
    else:
        get_receive_lsn_cmd += " -t -c  'select pg_last_wal_receive_lsn(); '"
    return exec_cmd(get_receive_lsn_cmd)


def get_current_lsn(ip):
    get_current_lsn_cmd = pg_bin_path + "psql -U postgres -h" + ip + " password=" + pg_password
    if pg_version == "9.6":
        get_current_lsn_cmd += " -t -c  'select pg_current_xlog_location();'"
    else:
        get_current_lsn_cmd += " -t -c  'select pg_current_wal_lsn();'"
    return exec_cmd(get_current_lsn_cmd)


def diff_lsn(lsn1, lsn2, *ip):
    lsn_diff_cmd = pg_bin_path + "psql -Upostgres "
    if len(ip) == 1:
        lsn_diff_cmd += "-h" + ip[0] + " password=" + pg_password 
    if pg_version != "9.6":
        lsn_diff_cmd += " -t -c \"select pg_wal_lsn_diff('" + lsn1 + "','" + lsn2 + "');\""
    else:
        lsn_diff_cmd += " -t -c \"select pg_xlog_location_diff('" + lsn1 + "','" + lsn2 + "');\""

    return exec_cmd(lsn_diff_cmd)


def get_delay_seconds():
    if not self_pg_ok():
        delay_seconds = -1
    elif get_self_role() == "primary":
        delay_seconds = 0
    else:
        primary_lsn = get_current_lsn(get_wvip())
        self_lsn = get_receive_lsn(get_self_ip())
        lsn_diff = diff_lsn(primary_lsn, self_lsn)
        if lsn_diff == "":
            delay_seconds = -1
        elif lsn_diff == "0":
            delay_seconds = 0
        else:
            get_delay_seconds_cmd = pg_bin_path + "psql -U postgres -t -c \"SELECT extract(epoch from now() - pg_last_xact_replay_timestamp()) AS standby_lag;\""
            delay_seconds = exec_cmd(get_delay_seconds_cmd)
            if delay_seconds == "":
                delay_seconds = -1
    return delay_seconds


def get_conn_cnt():
    return exec_cmd(pg_bin_path + "psql -U postgres -t -c \"select sum(numbackends) from pg_stat_database  where datname not in (\'postgres\');\"")


def get_deadlock_cnt():
    return exec_cmd(pg_bin_path + "psql -U postgres -t -c \"select sum(deadlocks) from pg_stat_database  where datname not in (\'postgres\');\"")


def ping_host(ip):
    ping_cmd = "ping -c 1 -w 1 " + ip + " > /dev/null 2>&1"
    return os.system(ping_cmd) == 0


def has_wal_receiver():
    receiver_one = exec_cmd("ps -ef | grep postgres | grep -v grep |grep 'receiver'") != ""
    time.sleep(1)
    receiver_two = exec_cmd("ps -ef | grep postgres | grep -v grep |grep 'receiver'") != ""
    return receiver_one and receiver_two


def get_self_status():
    role = get_self_role()
    if role == "primary":
        print(get_self_ip() + "\t\t" + role + "\t\t" + get_current_lsn(get_self_ip()) + "\t\t" + str(has_wal_receiver()) + "\t\t" + str(get_delay_seconds()))
    else:
        print(get_self_ip() + "\t\t" + role + "\t\t" + get_receive_lsn(get_self_ip()) + "\t\t" + str(has_wal_receiver()) + "\t\t" + str(get_delay_seconds()))


def cluster_status():
    print("ip \t\t role \t\t lsn \t\t wal_receiver \t\t delay_seconds")
    print("%s" % get_self_status())
    ip_list = get_other_ip_list()
    for ip in ip_list:
        print("%s" % exec_cmd("status", ip))


def get_wait_event_count():
    return exec_cmd("psql -U postgres -t -c \" SELECT count(*) FROM pg_stat_activity WHERE wait_event is NOT NULL and  datname not in (\'postgres\');\"")


def put_recovery_file():
    if get_self_role() == "primary":
        recovery_file = pg_data_path + "/recovery.done"
    else:
        recovery_file = pg_data_path + "/recovery.conf"
    fp = open(recovery_file, 'w')
    fp.write(recovery_conf_content)
    fp.close()
    logging.info("put %s" % recovery_file)
    exec_cmd("chown -R postgres:postgres " + pg_data_path)


def restore():
    logging.info("restore......")
    put_recovery_file()


def init():
    if os.path.exists(pg_data_path):
        return
    else:
        logging.info("mkdir data path and cp template data")
        os.makedirs(pg_data_path)
        exec_cmd("cp -rf " + template_data_path + "/* " + pg_data_path)
        os.chmod(pg_data_path, stat.S_IRWXU)


def get_db_name():
    return requests.get("http://metadata/self/env/db_name").text


def get_user_name():
    return requests.get("http://metadata/self/env/user_name").text


def get_passwd():
    return requests.get("http://metadata/self/env/password").text


def check_db_exists(db):
    check_db_cmd = "psql -U postgres -t -c '\l' |  awk 'gsub(/ /,\"\") {print $0}'|  awk  -F'|'  {'print $1}' | sed 's/ //g'|grep " + db
    return exec_cmd(check_db_cmd) != ""


def create_db(db):
    if not check_db_exists(db):
        logging.info("%s db does not exist, so create it")
        create_db_cmd = "psql -U postgres -d postgres -t -c \" create database " + db + "\""
        logging.info(exec_cmd(create_db_cmd))
    else:
        logging.info("%s db already exist, just exit" % db)


def check_user_exists(user_name):
    check_user_cmd = "psql -U postgres -t -c '\du' |  awk 'gsub(/ /,\"\") {print $0}'|  awk  -F'|'  {'print $1}' | sed 's/ //g'|grep " + user_name
    return exec_cmd(check_user_cmd) != ""


def create_user(user_name, passwd, db_name):
    if not check_user_exists(user_name):
        logging.info("user %s does not exist, so create it" % user_name)
        create_user_cmd = "psql -U postgres -d postgres -t -c \"CREATE USER " + user_name + " WITH PASSWORD '" + passwd + "';GRANT ALL PRIVILEGES ON DATABASE " + db_name + " to " + user_name + "\";"
        logging.info(exec_cmd(create_user_cmd))
    if not check_user_exists("root"):
        logging.info("create super user root")
        create_superuser_cmd = "psql -U postgres -d postgres -t -c \"CREATE USER root superuser password '" + passwd + "';\""
        logging.info(exec_cmd(create_superuser_cmd))


def check_pg_ok(ip):
    check_cmd = "psql --command \"SELECT 1;\" \"host=" + ip + " port=5432 user=postgres password=" + pg_password + " dbname=postgres\" -t| sed 's/ //g'"
    if exec_cmd(check_cmd) == "1":
            return True
    return False


def start():
    if get_self_role() == "primary":
        bind_vip(get_wvip())
    put_recovery_file()
    start_pg()
    start_lvs()


def stop():
    stop_pg()
    stop_lvs()

    
def start_pg():
    logging.info("start pg......")
    if get_self_role() == "standby":
        exec_cmd("su - postgres -c \"" + pg_bin_path + "/postgres -D " + pg_data_path + " -c max_connections=65535 -c config_file=" + pg_cfg_path + "/postgresql.conf >/dev/null &\"")
        time.sleep(3)
        exec_cmd("su - postgres -c \"" + pg_bin_path + "/pg_ctl -D " + pg_data_path + " stop\"")
    start_pg_cmd = "su - postgres -c \"" + pg_bin_path + "/postgres -D " + pg_data_path + " -c config_file=" + pg_cfg_path + "/postgresql.conf > /dev/null &\""
    exec_cmd(start_pg_cmd)
    time.sleep(1)
    if get_self_role() == "primary":
        create_db(get_db_name())
        create_user(get_user_name(), get_passwd(), get_db_name())


def stop_pg():
    logging.info("stop pg......")
    stop_pg_cmd = "su - postgres -c \"/usr/lib/postgresql/" + pg_version + "/bin/pg_ctl -D /data/pgsql/main stop   2>&1\""
    logging.info(exec_cmd(stop_pg_cmd))


def restart_pg():
    logging.info("restart pg......")
    stop_pg()
    start_pg()


def promote(*ip):
    if len(ip) == 1:
        logging.info("promote %s" % ip[0])
        exec_cmd("promote", ip[0])
    else:
        logging.info("promote......")
        exec_cmd("su - postgres -c \"" + pg_bin_path + "pg_ctl promote\"")


def demote():
    logging.info("demote......")
    os.rename(pg_data_path + "/recovery.done", pg_data_path + "/recovery.conf")


def bind_vip(vip):
    logging.info("bind vip......")
    logging.info(exec_cmd("/bin/ip addr add " + vip + "/24 dev eth0"))
    logging.info(exec_cmd("/usr/sbin/arping -q -c 3 -A " + vip + " -I eth0"))


def unbind_vip(vip):
    logging.info("unbind vip......")
    logging.info(exec_cmd("/bin/ip addr del " + vip + "/24 dev eth0"))
    logging.info(exec_cmd("/usr/sbin/arping -q -c 3 -A " + vip + " -I eth0"))


def get_commit_cnt_diff():
    commit_cnt_diff = 0
    commit_cmd = "psql -U postgres -t -c \"select sum(xact_commit) from pg_stat_database  where datname not in (\'postgres\',\'template1\');\""
    commit_cnt = exec_cmd(commit_cmd)
    if os.path.exists("/usr/lib/postgresql/scripts/tmppgdata_xact_commit"):
        get_last_commit_cnt_cmd = "cat /usr/lib/postgresql/scripts/tmppgdata_xact_commit"
        last_commit_cnt = exec_cmd(get_last_commit_cnt_cmd)
    else:
        last_commit_cnt = "0"
    try:    
        commit_cnt_diff = int(commit_cnt) - int(last_commit_cnt)
    except ValueError:
        os.unlink("/usr/lib/postgresql/scripts/tmppgdata_xact_commit")
    write_last_commit_cnt_cmd = ("echo " + commit_cnt + " >/usr/lib/postgresql/scripts/tmppgdata_xact_commit")
    exec_cmd(write_last_commit_cnt_cmd)
    return commit_cnt_diff


def backup():
    logging.info("backup by appcenter......")


def get_json_params(params=None):
    json_params = {}
    if params:
        json_params = json.loads(params[0])
    return json_params


def rebuild(ip=None):
    if ip is not None and get_json_params(ip[0]).get("node_ip", None) != get_self_ip():
        return 
    if get_self_role() == "primary":
        return 
    logging.info("rebuild me ......")
    del_realsrv(get_self_ip())

    logging.info("remove the old data")
    exec_cmd("rm -rf " + pg_data_path + "/*")

    logging.info("start pg_basebackup......")
    rebuild_cmd = pg_bin_path + "/pg_basebackup  -d \"host=" + get_wvip() + " port=5432 user=replica password=" + pg_password + "\" -F p -P -Xstream -D /data/pgsql/main/ -l replbackupBase4RebuildStandby"
    logging.info(exec_cmd(rebuild_cmd))

    logging.info("rename recovery file")
    os.rename(pg_data_path + "/recovery.done", pg_data_path + "/recovery.conf")
    exec_cmd("chown -R postgres:postgres " + pg_data_path)

    start_pg()
    add_realsrv(get_self_ip())


def del_realsrv(ip):
    logging.info("del realsrv %s ......" % ip)
    cmd = "ipvsadm -d -f 1 -r %s:%s >/dev/null 2>&1 &" % (ip, pg_port)
    exec_cmd(cmd, get_pg_ip_list()[0])
    exec_cmd(cmd, get_pg_ip_list()[1])


def add_realsrv(ip):
    logging.info("add realsrv %s ......" % ip)
    cmd = "ipvsadm -a -f 1 -r %s:%s >/dev/null 2>&1 &" % (ip, pg_port)
    exec_cmd(cmd, get_pg_ip_list()[0])
    exec_cmd(cmd, get_pg_ip_list()[1])


def get_max_conns():
    return requests.get("http://metadata/self/env/max_connections").text


def get_pg_mem():
    get_pg_mem_cmd = "curl -s http://metadata/self/hosts/pg/ | grep /memory | awk -F' ' {'print $2}'| sed 's/ //g'"
    mem = exec_cmd(get_pg_mem_cmd).splitlines()
    return mem[0]


def get_auto_optimized_max_conns():
    mem_size = get_pg_mem()
    return str(int(int(mem_size)/16))


def get_auto_optimized_shared_buffers():
    mem_size = get_self_mem()
    return str(int(int(mem_size)/4))


def get_shared_buffers():
    return requests.get("http://metadata/self/env/shared_buffers").text


def check_param_changed(param_name):
    param_in_use = exec_cmd(pg_bin_path + "psql -U postgres -t -c \"  show " + param_name + "; \"| sed 's/ //g'")
    param_in_file = exec_cmd("grep ^" + param_name + " " + pg_cfg_path + "/postgresql.conf | awk  -F' '  {'print $3}' | sed 's/ //g' ")
    if param_name == "shared_preload_libraries":
        param_in_file = requests.get("http://metadata/self/env/shared_preload_libraries").text
    if param_name == "shared_buffers":
        if "GB" in param_in_use:
            param_in_use = str(int(param_in_use[:-2])*1024) + "MB"
    if param_in_use != param_in_file:
        logging.info("%s has changed from %s to %s" % (param_name, param_in_use, param_in_file))
        return True
    return False


def check_need_restart():
    if not check_pg_ok(get_self_ip()):
        return False
    for param in need_restart_param_list:
        if check_param_changed(param):
            return True
    return False


#lzf
def check_need_pgpool_restart():
    for param in need_restart_pgpool_param_list:
        return True
    return False

    
def update_config_file():
    logging.info("update config file")
    exec_cmd("cat /etc/postgresql/" + pg_version + "/main/postgresql.conf.tmp > /etc/postgresql/" + pg_version + "/main/postgresql.conf")
    if is_sync_stream_repl():
        synchronous_standby_names = "FIRST 1 (" + get_best_successor().split('.')[-1] + ")"
        exec_cmd("sed -i \"s/synchronous_standby_names = ''/synchronous_standby_names = '" + synchronous_standby_names + "'/g\" " + pg_cfg_path + "/postgresql.conf")
    if get_max_conns() == "auto-optimized-conns":
        auto_optimized_max_conns = get_auto_optimized_max_conns()
        logging.info("set max_connections to auto_optimized_max_conns: %s" % auto_optimized_max_conns)
        exec_cmd("sed -i \"s/auto-optimized-conns/" + auto_optimized_max_conns + "/g\" /etc/postgresql/" + pg_version + "/main/postgresql.conf")
    if get_shared_buffers() == "auto-optimized-sharedbuffers":
        auto_optimized_shared_buffers = get_auto_optimized_shared_buffers()
        logging.info("set shared_buffers to auto_optimized_shared_buffers: %s" % auto_optimized_shared_buffers)
        exec_cmd("sed -i \"s/auto-optimized-sharedbuffers/" + auto_optimized_shared_buffers + "/g\" /etc/postgresql/" + pg_version + "/main/postgresql.conf")
    

#lzf
def update_pgpoolconfig_file():
    logging.info("set update_pgpoolconfig_file ...")
    num_init_children = auto_num_init_children()
    logging.info("set max_connections to num_init_children: %s" %cnum_init_children)
    exec_cmd("sed -i \"/^num_init_children =/num_init_children = " + num_init_children + "\" /usr/local/etc/pgpool.conf")
    
    
#lzf        
def get_max_pgpool():
    return requests.get("http://metadata/self/env/max_pool").text

#lzf    
def get_num_init_children():
     return requests.get("http://metadata/self/env/num_init_children").text
     
#lzf     
def auto_num_init_children():
    logging.info("set auto_num_init_children ...")
    auto_optimized_max_conns = get_auto_optimized_max_conns()
    logging.info("get get_auto_optimized_max_conns: %s " %auto_optimized_max_conns)
    max_pgpool = get_max_pgpool()
    logging.info("get get_max_pgpool: %s " %max_pgpool)
    pgpool_count = get_pgpool_count()
    logging.info("get get_pgpool_count: %s " %pgpool_count)
    if pgpool_count == 0:
        pgpool_count = 1
    init_children = get_num_init_children()
    num_init_children = int(int(auto_optimized_max_conns)/int(pgpool_count)/int(max_pgpool))
    if num_init_children > int(init_children):
        return init_children
    else:
        return num_init_children
    
#lzf
def get_pgpool_count():
    logging.info("get_pgpool_count ...")
    get_ip_cmd = "curl -s http://metadata/self/hosts/pgpool/ | grep /ip | wc -l | sed 's/ //g'| sort"
    ip_list = exec_cmd(get_ip_cmd).splitlines()
    return int(ip_list)
    
#lzf
def reload():
    logging.info("reload configuration")
    update_config_file()
    if check_need_restart():
        restart_pg()
    else:
        reload_cmd = "su - postgres -c \"" + pg_bin_path + "pg_ctl reload\""
        exec_cmd(reload_cmd)
    
    
    
#lzf        
def reload_pgpool():
    #需要从起pgpool的配置
    logging.info("reload_pgpool configuration")
    update_pgpoolconfig_file()
        

def health_check():
    logging.info("health check......")
    if os.path.exists(ignore_agent_path):
        logging.info("ignore_agent exists, so skip health check.")
        return 0
    if self_pg_ok():
        if get_self_role() == "standby" and not has_wal_receiver():
            logging.error("I am standby, but I have no wal receiver.")
            #lzf 检查出来pg出错时间
            if not (os.path.exists("/usr/lib/postgresql/scripts/tmppgdata_delaySeconds")):
                pg_error_time = time.time()
                write_pg_error_time = ("echo "+str(pg_error_time)+" > /usr/lib/postgresql/scripts/tmppgdata_delaySeconds")
                exec_cmd(write_pg_error_time)
            return 1
        else:
            logging.info("I am %s, and I am healthy." % get_self_role())
            return 0
    else:
        logging.error("I am %s, and pg is not alive." % get_self_role())
        return 1


#lzf
def standby_to_primary():
    #从节点落后主节点时间不是太长不切换
    cat_last_time = exec_cmd("cat /usr/lib/postgresql/scripts/tmppgdata_delaySeconds")
    now_time = time.time()
    if float(now_time) - float(cat_last_time) > 300:
        return False
    else:
        return True
    
    
    
    
def get_best_successor():
    ip_list = get_pg_ip_list()
    if get_self_ip() == ip_list[0]:
        return ip_list[1]
    else:
        return ip_list[0]


def self_pg_ok():
    grep_cmd = "ps -ef | grep 'postgres -D'| grep -v grep | awk '{print $2}'"
    return exec_cmd(grep_cmd) != ""


def health_check_action():
    logging.info("health check action......")
    if not check_pg_ok(get_self_ip()):
        logging.info("pg is not alive, so let's start pg")
        start()
        if self_pg_ok():
            logging.info("pg is started by health check action")
        else:
            logging.error("pg seems can not be started")
            if get_self_role() == "standby":
                logging.error("I am standby, there something wrong with the replication")
            elif auto_failover() and len(get_pg_ip_list()) > 1 and standby_to_primary():
                demote()
                unbind_vip(get_wvip())
                promote(get_best_successor())


def pg_rewind():
    logging.info("start pg_rewind......")
    pg_rewind_cmd = "su - postgres -c \"" + pg_bin_path + "/pg_rewind --target-pgdata " + pg_data_path + " --source-server='host=" + get_wvip() + " port=5432 user=postgres password=" + pg_password + "'\""
    logging.info(exec_cmd(pg_rewind_cmd))
    logging.info("rename recover.done carried by pg_rewind")
    demote()


def run_hook(path):
    if os.path.exists(path):
        logging.info("run hook %s......" % path)
        exec_cmd(path)


def monitor():
    print("{\"delay_seconds\": %s,\"conn_cnt\": %s,\"commit_cnt\": %s,\"deadlock_cnt\": %s,\"wait_event_cnt\": %s}" % (get_delay_seconds(), get_conn_cnt(), get_commit_cnt_diff(), get_deadlock_cnt(), get_wait_event_count()))


def get_nodes_detail():
    nodes_id = exec_cmd("curl -s http://metadata/self/hosts/pg|grep node_id |  awk  -F' '  {'print $2}' | sed 's/ //g'").splitlines()
    nodes_ip = exec_cmd("curl -s http://metadata/self/hosts/pg|grep /ip |  awk  -F' '  {'print $2}' | sed 's/ //g'").splitlines()
    nodes_detail = []
    for i in range(len(nodes_ip)):
        nodes_detail.append([nodes_id[i], nodes_ip[i], get_role_by_sql(nodes_ip[i])])
    pg_nodes_detail = {
        "labels": ["node_id", "node_ip", "role"],
        "data": nodes_detail
    }
    print(json.dumps(pg_nodes_detail))
    logging.info(json.dumps(pg_nodes_detail))


def get_role_by_sql(ip):
    return exec_cmd("psql -U postgres -h " + ip + " password=" + pg_password + " -t -c \" select  (case when  pg_is_in_recovery()  ='true'  then 'standby'  else  'primary' end);\"| sed 's/ //g'")


def get_added_ip_list():
    return exec_cmd("curl -s http://metadata/self/adding-hosts/ |grep /ip |  awk  -F' '  {'print $2}' | sed 's/ //g'").splitlines()


def get_deleted_ip_list():
    return exec_cmd("curl -s http://metadata/self/deleting-hosts/ |grep /ip |  awk  -F' '  {'print $2}' | sed 's/ //g'").splitlines()


def scale_out():
    logging.info("scale out ......")
    restart_lvs()
    if get_self_role() == "standby":
        return
    else:
        for ip in get_added_ip_list():
            logging.info("rebuid  %s......" % ip)
            exec_cmd("rebuild", ip)


def scale_in():
    logging.info("scale in ......")
    restart_lvs()


def get_keepalived_role():
    if get_self_ip() == get_pg_ip_list()[0]:
        return "MASTER"
    elif get_self_ip() == get_pg_ip_list()[1]:
        return "BACKUP"
    else:
        return ""


def start_lvs():
    rvip = get_rvip()
    if gene_lvs_conf_file(get_keepalived_role()):
        exec_cmd("ipvsadm --set %s 4 120 ;/etc/init.d/keepalived start" % lvs_wait_timeout)
    add_lo = """\
            /sbin/ifconfig lo down;
            /sbin/ifconfig lo up;
            echo 1 > /proc/sys/net/ipv4/conf/lo/arp_ignore;
            echo 2 > /proc/sys/net/ipv4/conf/lo/arp_announce;
            echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore;
            echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce;
            /sbin/ifconfig lo:0 %s broadcast %s netmask 255.255.255.255 up;
            /sbin/route add -host %s dev lo:0;
        """ % (rvip, rvip, rvip)
    exec_cmd(add_lo)


def restart_lvs():
    logging.info("restart lvs......")
    stop_lvs()
    start_lvs()


def stop_lvs():
    logging.info("stop lvs......")
    del_lo = """\
            /sbin/ifconfig lo:0 down;
            echo 0 > /proc/sys/net/ipv4/conf/lo/arp_ignore;
            echo 0 > /proc/sys/net/ipv4/conf/lo/arp_announce;
            echo 0 > /proc/sys/net/ipv4/conf/all/arp_ignore;
            echo 0 > /proc/sys/net/ipv4/conf/all/arp_announce;
        """
    exec_cmd(del_lo)
    exec_cmd("/etc/init.d/keepalived stop")


def get_net_prefix(ip):
    net_prefix = ip
    if ip:
        parts = ip.split(".")
        net_prefix = "%s.%s.%s." % (parts[0], parts[1], parts[2])
    return net_prefix


def get_ip_used_eth(ip):
    net_prefix = get_net_prefix(ip)
    get_dev_cmd = "ifconfig | grep -B 1 'inet addr:%s' | grep HWaddr | awk '{print $1}'" % net_prefix
    dev = exec_cmd(get_dev_cmd)
    return dev


def gene_lvs_conf_file(role):
    logging.info("generate lvs conf ......")
    if role == "":
        logging.info("it's not a master or backup of keepalived,so there is no need to generate configuration files")
        return False

    eth = get_ip_used_eth(get_self_ip())
    if not eth:
        logging.error("generate lvs conf failed")
        return False

    lvs_global_conf = """ 
        global_defs {
            router_id %s
        }
    """ % (get_rvip())

    unicast_peer = ""    
    for ip in get_other_ip_list():
        unicast_peer += ip + "\n"
    unicast_conf = """ 
            unicast_src_ip %s
            unicast_peer {
                %s
            }
        """ % (get_self_ip(), unicast_peer)

    priority = 200
    nopreempt = ""
    if role == "MASTER":
        priority += 50

    vrrp_conf = """ 
        vrrp_instance VI_1 {
            state %s
            %s
            interface %s
            virtual_router_id 100
            priority %s

            %s

            advert_int 2
            authentication {
                auth_type PASS
                auth_pass pass
            }
            virtual_ipaddress {
                %s
            }
        } """ % (role, nopreempt, eth, priority, unicast_conf, get_rvip())

    rslist = get_scaled_iplist()
    if role == "BACKUP":
        rslist.remove(get_pg_ip_list()[0])
    
    rs_conf = ""
    for rsip in rslist:
        rs_conf += """
            real_server %s %s {
                weight 1
                MISC_CHECK {
                    misc_path "/usr/lib/postgresql/scripts/pgmanager.py load_read_request %s"
                    misc_timeout 60
                }
            }
            """ % (rsip, pg_port, rsip)

    vip_conf_head = "virtual_server %s %s" % (get_rvip(), pg_port)
    vip_conf = """
        %s {
            delay_loop 10
            lb_algo rr
            lb_kind DR
            nat_mask 255.255.255.0
            protocol TCP

        %s

     } """ % (vip_conf_head, rs_conf)
    lvsconf = lvs_global_conf + vrrp_conf + vip_conf
    return write_file(keepalived_conf, lvsconf)


def write_file(file_name, content):
    try:
        with open(file_name, "w") as f:
            f.write("%s" % content)
            f.flush()
            os.fsync(f.fileno())
    except OSError as reason:
        logging.error("write file [%s] failed, [%s]" % (file_name, reason))
        return False
    f.close()
    logging.info("write file [%s] success" % file_name)
    return True


def load_read_request(ip):
    if not check_pg_ok(ip):
        return -1
    load_read_request_to_primary = requests.get("http://metadata/self/env/load_read_request_to_primary").text
    if load_read_request_to_primary == "No" and get_role_by_sql(ip) == "primary":
        return 1
    return 0


def is_sync_stream_repl():
    return requests.get("http://metadata/self/env/sync_stream_repl").text == "Yes"


def get_self_mem():
    return requests.get("http://metadata/self/host/memory").text


def get_pool_user_name():
    return exec_cmd("curl -s http://metadata | grep user_name| head -n 1 | awk -F' ' {'print $2}'| sed 's/ //g'")


def get_pool_passwd():
    return exec_cmd("curl -s http://metadata | grep password| head -n 1 | awk -F' ' {'print $2}'| sed 's/ //g'")


#lzf
def get_userpasswd_pgpool():
    while True:
        wvip = get_wvip()
        time.sleep(3)
        if check_pg_ok(wvip):
            rows = exec_cmd(pg_bin_path +"psql -Upostgres  -h" + wvip + " password='"+pg_password+"' -t -c 'select usename,passwd from pg_shadow;'")
            row = rows.replace("|",":")
            up = row.replace(" ","")
            write_file("/usr/local/etc/pool_passwd",up)
            logging.info("start pg writer usepass to pgpool succeed")
            break
        else:
            logging.info("start pg writer usepass to pgpool fail... reason pg not starting")
            write_file("/usr/local/etc/pool_passwd","")
        

def start_pgpool():
    logging.info("start pgpool......")
    get_userpasswd_pgpool()
    exec_cmd("pg_md5 --md5auth --username=%s %s" % (get_pool_user_name(), get_pool_passwd()))
    exec_cmd("pg_md5 --md5auth --username=postgres QY3.14coolpg")
    exec_cmd("/usr/local/bin/pgpool -n >> /data/pglog/pgpool.log 2>&1 &")


def stop_pgpool():
    logging.info("stop pgpool......")
    exec_cmd("/usr/local/bin/pgpool -m fast stop")


def restart_pgpool():
    logging.info("restart pgpool......")
    stop_pgpool()
    reload_pgpool()
    start_pgpool()


def health_check_pgpool():
    grep_cmd = "ps -ef | grep 'pgpool -n'| grep -v grep | awk '{print $2}'"
    if exec_cmd(grep_cmd) != "":
        return 0
    else:
        return 1

def health_check_action_pgpool():
    start_pgpool()
