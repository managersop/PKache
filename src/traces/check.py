if __name__ == "__main__":
    # with open(r'/home/dor/NetCache/currenttmp', 'rb') as f:
    #     data = f.readlines()
    # print (len(data))
    # strip = list(map(lambda x: x.split()[2], data))
    # print(len(strip))
    # uniq = list(set(strip))
    # print(len(uniq))
    # counter = 1
    # printed = {}
    # trace = []
    # for i in strip:
    #     if i in printed.keys():
    #         trace.append(str(printed[i]) + '\n')
    #     else:
    #         printed[i] = counter
    #         trace.append(str(counter) + '\n')
    #         counter += 1
    # print(len(printed))
    # print(len(trace))
    # with open('/home/dor/NetCache/wiki.1192951682.txt', 'w') as f:
    #     f.writelines(trace)
    with open('/home/dor/dev/Thesis/src/traces/WebSearch1.spc', 'r') as f:
        data = f.readlines()
    print (len(data))
    strip = list(map(lambda x: x.split(',')[1], data))
    print(len(strip))
    uniq = list(set(strip))
    print(len(uniq))
    counter = 1
    printed = {}
    trace = []
    for i in strip:
        if i in printed.keys():
            trace.append(str(printed[i]) + '\n')
        else:
            printed[i] = counter
            trace.append(str(counter) + '\n')
            counter += 1
    print(len(printed))
    print(len(trace))
    with open('/home/dor/dev/Thesis/src/traces/ws1.txt', 'w') as f:
        f.writelines(trace)
