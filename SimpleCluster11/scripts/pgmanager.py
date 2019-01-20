#!/usr/bin/python3
import sys
import pgutils

supported_action = ["init", "start", "stop", "restart", "restore", "status", "cluster_status", "backup", "rebuild", "health_check", "health_check_action", "scale_out", "scale_in", "monitor", "nodes_detail", "rewind", "promote", "reload","load_read_request"]


def print_usage():
    print("usage: pgmanager action")
    print("supported action:" + str(supported_action))

if __name__ == "__main__":
    argc = len(sys.argv)
    if (argc < 2) or (sys.argv[1] not in supported_action):
        print_usage()
        sys.exit(1) 

    action = sys.argv[1]
    pgutils.run_hook("/data/before_" + action + ".sh")
    if action == "init":
        pgutils.init()
    elif action == "start":
        pgutils.start()
    elif action == "stop":
        pgutils.stop()
    elif action == "restart":
        pgutils.restart_pg()
    elif action == "status":
        pgutils.get_self_status()
    elif action == "cluster_status":
        pgutils.cluster_status()
    elif action == "backup":
        pgutils.backup()
    elif action == "restore":
        pgutils.restore()
    elif action == "rebuild":
        if argc > 2:
            pgutils.rebuild(sys.argv[2:])
        else:
            pgutils.rebuild()
    elif action == "health_check":
        exit(pgutils.health_check())
    elif action == "health_check_action":
        pgutils.health_check_action()
    elif action == "scale_out":
        pgutils.scale_out()
    elif action == "scale_in":
        pgutils.scale_in()
    elif action == "monitor":
        pgutils.monitor()
    elif action == "reload":
        pgutils.reload()
    elif action == "nodes_detail":
        pgutils.get_nodes_detail()
    elif action == "rewind":
        pgutils.pg_rewind()
    elif action == "promote":
        pgutils.promote()
        pgutils.bind_vip(pgutils.get_wvip())
    elif action == "load_read_request":
        exit(pgutils.load_read_request(sys.argv[2]))
    pgutils.run_hook("/data/after_" + action + ".sh")
