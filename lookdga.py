import argparse
from datetime import datetime, timedelta
import dga
from sys import argv


class Col:
    HEADER = '\033[95m\033[1m'
    INFO = '\033[96m'
    OK = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--date",
                        help="date when domains are generated, e.g., 2021-06-28 (default today)")
    parser.add_argument("-b", "--backdays",
                        help="days to search when bruteforcing a domain (default 366 days)", type=int, default=366)
    parser.add_argument("-n",
                        help="number of domain generated (default N=10)")
    parser.add_argument("-m", "--malware",
                        help="malware to use as domain generator (default all malwares)", nargs="+", type=str)
    parser.add_argument("-s", "--seed",
                        help="seed used in the malware DGA (default depends of malware)", type=str)
    group_commands = parser.add_mutually_exclusive_group()
    group_commands.add_argument("-L", "--list",
                                help="list samples of DGA malware knowed", action="store_true")
    group_commands.add_argument("-I", "--info",
                                help="show info of DGA malware (all if not DGA selected)", action="store_true")
    group_commands.add_argument("-G", "--generate",
                                help="generate domains of DGA malware (all knowed if no malware specified)", action="store_true")
    group_commands.add_argument("-C", "--create",
                                help="create as many samples per family as number indicated in -n (all knowed families if no malware specified)",
                                action="store_true")
    group_commands.add_argument("-D", "--detect", nargs="+", type=str,
                                help="try to detect if a domain/s belongs to a DGA malware family")
    group_commands.add_argument("-B", "--bruteforce", nargs="+", type=str,
                                help="try to detect the date and position of a domain bruteforcing this field of a malware family")
    group_commands.add_argument("-F", "--firewall",
                                help="generate a domain list for the next seven days of all malware known",
                                action="store_true")
    args = parser.parse_args()

    if args.date:
        try:
            date = datetime.strptime(args.date, "%Y-%m-%d")
        except:
            print("* Date passed in wrong format: " + Col.ERROR + f"{args.date}" + Col.END)
            print(f"* Use YYYY-MM-DD format (e.g. 2021-05-25)")
            exit()
    else:
        date = datetime.now()

    if args.seed:
        seed = args.seed
    else:
        seed = None

    if args.malware:
        try:
            malware = []
            for item in args.malware:
                if eval(f"dga.{item}").DGA.shortname == item:
                    malware.append(item)
        except:
            print("* Unknown malware name " + Col.ERROR + f"{item}" + Col.END)
            print(f"* Try running {argv[0]} with -L option to see all malware families:")
            print(Col.INFO + f"  {argv[0]} -L" + Col.END)
            exit()
    else:
        malware = dga.listall()

    if args.n:
        try:
            nr = int(args.n)
        except:
            print("* Wrong number format: " + Col.ERROR + f"{args.n}" + Col.END)
            print(f"* Use an integer (e.g. 50)")
            exit()
    else:
        nr = 10

    if args.list:
        dga.listall(main=True)
    elif args.generate:
        dga.generate(malware, date, nr, seed, main=True)
    elif args.create:
        dga.create(malware, date, nr, seed, main=True)
    elif args.info:
        dga.info(malware, main=True)
    elif args.detect:
        dga.detect(malware, args.detect, main=True)
    elif args.bruteforce:
        dga.bruteforce(malware, args.bruteforce, date, seed, nr, days=args.backdays, main=True)
    elif args.firewall:
        domains = []
        for d in range(0, 8):
            for domain in dga.create(malware, date + timedelta(days=d), nr, None, main=False):
                if domain[0] not in domains:
                    domains.append(domain[0])
                    print(domain[0])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
