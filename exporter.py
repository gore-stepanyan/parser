from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
from time import sleep
from math import sin, cos

i = 0.0
while True:
    registry = CollectorRegistry()
    g = Gauge('r_factor', 'computed according to e-model', registry=registry)
    g.set_to_current_time()
    g.set(sin(i))

    hh = Gauge('MOS', 'computed according to e-model', registry=registry)
    hh.set_to_current_time()
    hh.set((cos(i) * 5))
    push_to_gateway('localhost:9091', job='call-ID: asdfgvc14', registry=registry)

    registry = CollectorRegistry()

    gg = Gauge('MOS', 'computed according to e-model', registry=registry)
    gg.set_to_current_time()
    gg.set((sin(i) * 5))

    h = Gauge('r_factor', 'computed according to e-model', registry=registry)
    h.set_to_current_time()
    h.set(cos(i))
    push_to_gateway('localhost:9091', job='call-ID: qwedffvujh1', registry=registry)

    i = i + 0.01
    sleep(0.5)