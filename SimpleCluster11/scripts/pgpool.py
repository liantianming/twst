#!/usr/bin/python3
import sys
import pgutils

supported_action = ["start", "stop", "restart", "health_check", "health_check_action"]


def print_usage():
    print("usage: pgpoool action")
    print("supported action:" + str(supported_action))

if __name__ == "__main__":
    argc = len(sys.argv)
    if (argc < 2) or (sys.argv[1] not in supported_action):
        print_usage()
        sys.exit(1) 

    action = sys.argv[1]
    pgutils.run_hook("/data/before_" + action + ".sh")
    if action == "start":
        pgutils.start_pgpool()
    elif action == "stop":
        pgutils.stop_pgpool()
    elif action == "restart":
        pgutils.restart_pgpool()
    elif action == "health_check":
        exit(pgutils.health_check_pgpool())
    elif action == "health_check_action":
        pgutils.health_check_action_pgpool()
    pgutils.run_hook("/data/after_" + action + ".sh")
