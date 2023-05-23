import time
import requests
import concurrent.futures

class Handler(object):
    def handle(self, packet: str):
        time.sleep(1)
        print(packet + ' handled')

def listen():
    i = 0
    while i < 10:
        yield 'packet ' + str(i)
        i = i + 1

h1 = Handler()
h2 = Handler()
h3 = Handler()

hanlers = [h1, h2, h3]

print("Running threaded:")
threaded_start = time.time()
with concurrent.futures.ThreadPoolExecutor() as executor:
    for p in listen():
        futures = []
        for handler in hanlers:
            futures.append(executor.submit(handler.handle, packet = p))
        #for future in concurrent.futures.as_completed(futures):
            #print(future.result())
print("Threaded time:", time.time() - threaded_start)