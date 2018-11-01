class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


KEYSPACE_MIN_VALUE = 1000


def c_out(param, color_code):

    print(color_code+param+Colors.ENDC, flush=True)


def calculate_workload(nodes:list, keypsace: int):
    '''
    :param nodes:
    nodes = [(score, rank),  ]
    :param keypsace: should be integer
    :return: it returns {rank: (skip, limit)}
    '''
    results = {}
    div = len(nodes)
    legacy = 0
    legacy_rank = 0
    total_score = 0
    for item in nodes:
        total_score += item[0]
        if item[0] > legacy:
            legacy = item[0]
            legacy_rank = item[1]

    remain = keypsace % total_score
    divisable = keypsace - remain
    k = int(divisable / total_score)

    skip = 0
    do_once = True
    for item in nodes:
        limit = item[0]*k
        if item[1] == legacy_rank and do_once:
            limit += remain
            do_once = False
        results[item[1]] = (skip, limit)
        skip = limit + skip

    return results


