import time
import concurrent.futures
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway


class Handler(object):
    __slots__ = (
        'count',
        'name'
    )

    def __init__(self, name: str):
        self.count = 0
        self.name = name

    def handle(self, packet: str):
        time.sleep(0.6)
        self.count = self.count + 1
        #print(packet + ' handled')

def listen():
    i = 0
    while True:
        yield 'packet ' + str(i)
        i = i + 1
        time.sleep(0.5)
        
h1 = Handler('joe')
h2 = Handler('bob')
h3 = Handler('ash')

handlers = [h1, h2, h3]

def hello():
    while True:
        time.sleep(5)        
        print('hello!')
        for handler in handlers:
            registry = CollectorRegistry()
            hh = Gauge('count', 'packets_counted', registry=registry)
            hh.set_to_current_time()
            hh.set(handler.count)
            push_to_gateway('localhost:9091', job=handler.name, registry=registry)

def func():

    print("Running threaded:")
    threaded_start = time.time()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.submit(hello)
        for p in listen():
            futures = []
            for handler in handlers:
                futures.append(executor.submit(handler.handle, packet = p))
            #for future in concurrent.futures.as_completed(futures):
                #print(future.result())
    print("Threaded time:", time.time() - threaded_start)

try:
    func()
except:
    exit()