LFU = 'F'
FIFO = 'O'
LRU = 'R'


class Element:
    def __init__(self, key, lfu_counter, lru_counter):
        self.key = key
        self.lfu_counter = lfu_counter
        self.lru_counter = lru_counter


class Cache:
    def __init__(self, size, k, policy):
        self.k = k
        self.size = size
        self.elements = []
        self.policy = policy
        for i in range(k):
            self.elements.append([])

    def is_key_in_cache(self, key):
        return len(list(filter(lambda x: x.key == key, self.elements[key % self.k]))) == 1

    def get_element(self, key, position=None):
        if len(self.elements[key % self.k]) == 0:
            return None
        if position:
            return self.elements[key % self.k][position]
        else:
            return self.elements[key % self.k][-1]

    def update_element_lfu_counter(self, key):
        for i in range(len(self.elements[key % self.k])):
            if self.elements[key % self.k][i].key == key:
                self.elements[key % self.k][i].lfu_counter += 1

    def update_element_lru_counter(self, key, timestamp):
        for i in range(len(self.elements[key % self.k])):
            if self.elements[key % self.k][i].key == key:
                self.elements[key % self.k][i].lru_counter = timestamp

    def get_element_position_with_minimum_lfu_counter(self, key):
        min = 2 ** 32 - 1
        pos = 0
        for i in range(len(self.elements[key % self.k])):
            if self.elements[key % self.k][i].lfu_counter <= min:
                pos = i
                min = self.elements[key % self.k][i].lfu_counter
        return pos

    def get_element_position_with_minimum_lru_counter(self, key):
        min = 2 ** 32 - 1
        pos = 0
        for i in range(len(self.elements[key % self.k])):
            if self.elements[key % self.k][i].lru_counter <= min:
                pos = i
                min = self.elements[key % self.k][i].lru_counter
        return pos

    def is_cache_full(self, key):
        return len(self.elements[key % self.k]) == self.size

    def insert_to_cache(self, key, elem):
        if not self.is_cache_full(key):
            for i in range(len(self.elements[key % self.k]) - 1): # Decrement LFU counter
                if self.elements[key % self.k][i].lfu_counter > 0:
                    self.elements[key % self.k][i].lfu_counter -= 1
            if self.policy == LFU or self.policy == LRU:
                self.elements[key % self.k].append(elem)
            elif self.policy == FIFO:
                self.elements[key % self.k] = [elem] + self.elements[key % self.k]
            return None
        else:
            if self.policy == LFU:
                pos = self.get_element_position_with_minimum_lfu_counter(key)
            elif self.policy == LRU:
                pos = self.get_element_position_with_minimum_lru_counter(key)
            else:
                pos = len(self.elements[key % self.k]) - 1
            
            for i in range(len(self.elements[key % self.k])):
                if i == pos:
                    if self.policy == FIFO:
                        victim = self.elements[key % self.k].pop()
                        self.elements[key % self.k] = [elem] + self.elements[key % self.k]
                    else:
                        victim = self.elements[key % self.k][i]
                        self.elements[key % self.k][i] = elem
                else:
                    if self.elements[key % self.k][i].lfu_counter > 0:
                        self.elements[key % self.k][i].lfu_counter -= 1
            return victim


K = 1
MAIN_SIZE = 2
FRONT_SIZE = 1

MAIN_CACHE = Cache(MAIN_SIZE, K, LFU)
FRONT_CACHE = Cache(FRONT_SIZE, K, FIFO)
GLOBAL_COUNTER = dict()
COUNTER = 0

def process_key(key, counter):
    # if key % 16 != 3:
    #     return None
    GLOBAL_COUNTER[key] = GLOBAL_COUNTER.get(key, 0) + 1
    in_front_cache = FRONT_CACHE.is_key_in_cache(key)
    in_main_cache = MAIN_CACHE.is_key_in_cache(key)
    if in_front_cache:
        FRONT_CACHE.update_element_lfu_counter(key)
        FRONT_CACHE.update_element_lru_counter(key, counter)
        return (1, 0, 0)
    if in_main_cache:
        MAIN_CACHE.update_element_lfu_counter(key)
        MAIN_CACHE.update_element_lru_counter(key, counter)
        return (0, 1, 0)
    victim = FRONT_CACHE.insert_to_cache(key, Element(key, 1, counter))
    if not victim:
        return (0, 0, 1)
    else:
        if not MAIN_CACHE.is_cache_full(victim.key):
            MAIN_CACHE.insert_to_cache(victim.key, victim)
            return (0, 0, 1)
        else:
            insert = True
            if MAIN_CACHE.policy == LFU:
                potential_victim = MAIN_CACHE.get_element(victim.key, MAIN_CACHE.get_element_position_with_minimum_lfu_counter(victim.key))
                insert = potential_victim.lfu_counter < victim.lfu_counter
            elif MAIN_CACHE.policy == LRU:
                potential_victim = MAIN_CACHE.get_element(victim.key, MAIN_CACHE.get_element_position_with_minimum_lfu_counter(victim.key))
                insert = potential_victim.lru_counter < victim.lru_counter
            else:
                potential_victim = MAIN_CACHE.get_element(victim.key)
            if potential_victim and insert and GLOBAL_COUNTER[potential_victim.key] <= GLOBAL_COUNTER[victim.key]:
                MAIN_CACHE.insert_to_cache(victim.key, victim)
                return (0, 0, 1)
            else:
                return (0, 0, 1)


if __name__ == "__main__":
    # with open('/home/dor/dev/PKache/src/pKway-tcam-multi/OLTP.lis', 'r') as f:
    #     data = list(filter(lambda x: x < 65530, map(lambda x: int(x.split(' ')[0]), f.readlines())))
    # with open('/home/dor/dev/PKache/src/pKway-tcam-multi/OLTP.lis', 'r') as f:
    #     data = list(map(lambda x: int(x.split(' ')[0]), f.readlines()))
    # with open('/home/dor/dev/PKache/src/pKway-tcam-multi/WebSearch1.spc', 'r') as f:
    #     data = list(map(lambda x: int(x.split(',')[1]), f.readlines()))
    with open('/home/dor/dev/PKache/src/pKway-tcam-multi/query.txt', 'r') as f:
        data = list(map(lambda x: int(x), f.readlines()))
    
    data = (1,1,2,3,3,3,4,1)
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
            print(int(x), int(x)%16, ret)
        i += 1

        if (i > 0 and i % 100 == 0):
            print(i)
            print('Hit front ', hit_front)
            print('Hit main ', hit_main)
            print('Hit miss ', hit_miss)
            print((hit_front + hit_main) / i)
        if i == 1000:
            break


    print('Hit front ', hit_front)
    print('Hit main ', hit_main)
    print('Hit miss ', hit_miss)
    print((hit_front + hit_main) / (hit_front + hit_main + hit_miss))
