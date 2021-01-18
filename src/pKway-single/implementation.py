LFU = 'F'
FIFO = 'O'
LRU = 'R'
HYPER = 'H'


class Element:
    def __init__(self, key, lfu_counter, lru_counter, insertion_time, n):
        self.key = key
        self.lfu_counter = lfu_counter
        self.lru_counter = lru_counter
        self.insertion_time = insertion_time
        self.n = n


class Cache:
    def __init__(self, size, d, policy):
        self.d = d
        self.size = size
        self.elements = []
        self.policy = policy
        for i in range(d):
            self.elements.append([])

    def is_key_in_cache(self, key):
        return len(list(filter(lambda x: x.key == key, self.elements[key % self.d]))) == 1

    def get_element(self, key, position=None):
        if len(self.elements[key % self.d]) == 0:
            return None
        if position:
            return self.elements[key % self.d][position]
        else:
            return self.elements[key % self.d][-1]

    def update_element_lfu_counter(self, key):
        for i in range(len(self.elements[key % self.d])):
            if self.elements[key % self.d][i].key == key:
                self.elements[key % self.d][i].lfu_counter += 1

    def update_element_lru_counter(self, key, timestamp):
        for i in range(len(self.elements[key % self.d])):
            if self.elements[key % self.d][i].key == key:
                self.elements[key % self.d][i].lru_counter = timestamp

    def update_element_hyper_counter(self, key):
        for i in range(len(self.elements[key % self.d])):
            if self.elements[key % self.d][i].key == key:
                self.elements[key % self.d][i].n += 1

    def get_element_position_with_minimum_lfu_counter(self, key):
        min = 2 ** 32 - 1
        min_lru = 2 ** 32 - 1
        pos = 0
        for i in range(len(self.elements[key % self.d])):
            if self.elements[key % self.d][i].lfu_counter <= min and self.elements[key % self.d][i].lru_counter <= min_lru:
                pos = i
                min = self.elements[key % self.d][i].lfu_counter
                min_lru = self.elements[key % self.d][i].lru_counter
        return pos

    def get_element_position_with_minimum_lru_counter(self, key):
        min = 2 ** 32 - 1
        pos = 0
        for i in range(len(self.elements[key % self.d])):
            if self.elements[key % self.d][i].lru_counter <= min:
                pos = i
                min = self.elements[key % self.d][i].lru_counter
        return pos

    def get_element_position_with_minimum_hyper_counter(self, key, timestamp):
        min = 2 ** 32 - 1
        pos = 0
        for i in range(len(self.elements[key % self.d])):
            if (self.elements[key % self.d][i].n / (timestamp -self.elements[key % self.d][i].insertion_time)) <= min:
                pos = i
                min = (self.elements[key % self.d][i].n / (timestamp -self.elements[key % self.d][i].insertion_time))
        return pos

    def is_cache_full(self, key):
        return len(self.elements[key % self.d]) == self.size

    def insert_to_cache(self, key, elem, timestamp):
        if not self.is_cache_full(key):
            # for i in range(len(self.elements[key % self.d]) - 1): # Decrement LFU counter
            #     if self.elements[key % self.d][i].lfu_counter > 0:
            #         self.elements[key % self.d][i].lfu_counter -= 1
            if self.policy == LFU or self.policy == LRU or self.policy == HYPER:
                self.elements[key % self.d].append(elem)
            elif self.policy == FIFO:
                self.elements[key % self.d] = [elem] + self.elements[key % self.d]
            return None
        else:
            if self.policy == LFU:
                pos = self.get_element_position_with_minimum_lfu_counter(key)
            elif self.policy == LRU:
                pos = self.get_element_position_with_minimum_lru_counter(key)
            elif self.policy == HYPER:
                pos = self.get_element_position_with_minimum_hyper_counter(key, timestamp)
            else:
                pos = len(self.elements[key % self.d]) - 1
            
            for i in range(len(self.elements[key % self.d])):
                if i == pos:
                    if self.policy == FIFO:
                        victim = self.elements[key % self.d].pop()
                        self.elements[key % self.d] = [elem] + self.elements[key % self.d]
                    else:
                        victim = self.elements[key % self.d][i]
                        self.elements[key % self.d][i] = elem
                # else:
                #     if self.elements[key % self.d][i].lfu_counter > 0:
                #         self.elements[key % self.d][i].lfu_counter -= 1
            return victim


D = 32
FRONT_SIZE = 16

FRONT_CACHE = Cache(FRONT_SIZE, D, LRU)
GLOBAL_COUNTER = dict()
COUNTER = 0

def process_key(key, counter):
    # if key % 16 != 3:
    #     return None
    GLOBAL_COUNTER[key] = GLOBAL_COUNTER.get(key, 0) + 1
    in_front_cache = FRONT_CACHE.is_key_in_cache(key)
    if in_front_cache:
        FRONT_CACHE.update_element_lfu_counter(key)
        FRONT_CACHE.update_element_lru_counter(key, counter)
        FRONT_CACHE.update_element_hyper_counter(key)
        return (1, 0, 0)
    victim = FRONT_CACHE.insert_to_cache(key, Element(key, 1, counter, counter, 1), counter)
    return (0, 0, 1)


if __name__ == "__main__":
#     with open('/home/dor/dev/Thesis/src/traces/OLTP.lis', 'r') as f:
#         data = list(map(lambda x: int(x.split(' ')[0]), f.readlines()))
    # with open('/home/dor/dev/Thesis/src/traces/query0.99.txt', 'r') as f:
    #     data = list(map(lambda x: int(x), f.readlines()))
    with open('/home/dor/dev/Thesis/src/traces/wiki.1192951682.txt', 'rb') as f:
        data = list(map(lambda x: int(x), f.readlines()))
    # with open('/home/dor/dev/Thesis/src/traces/ws1.txt', 'rb') as f:
    #     data = list(map(lambda x: int(x), f.readlines()))
    
    
    print(len(data))
    hit_front = 0
    hit_main = 0
    hit_miss = 0
    i = 0
    counter = 0

    for x in data:
        ret = process_key(int(x), i)
        if ret:
            hit_front += ret[0]
            hit_main += ret[1]
            hit_miss += ret[2]
            # print(int(x), int(x)%16, ret)
        i += 1

        if (i > 0 and i % 100 == 0):
            print(i)
            print('Hit front ', hit_front)
            print('Hit main ', hit_main)
            print('Hit miss ', hit_miss)
            print((hit_front + hit_main) / i)


    print('Hit front ', hit_front)
    print('Hit main ', hit_main)
    print('Hit miss ', hit_miss)
    print((hit_front + hit_main) / (hit_front + hit_main + hit_miss))
