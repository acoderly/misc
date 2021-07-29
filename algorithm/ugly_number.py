#计算第1500个丑数
#1,2,3,4,5
import datetime

startTime = datetime.datetime.now()

uglyNumberList = [1]
indexList = [[0,2], [0,3], [0,5]]

while len(uglyNumberList) <= 1500:
    var = min(uglyNumberList[indexList[0][0]]*2, uglyNumberList[indexList[1][0]]*3, uglyNumberList[indexList[2][0]]*5)
    for i in range(0, 3):
        if uglyNumberList[indexList[i][0]]*indexList[i][1] == var:
            indexList[i][0] += 1
    else:
        uglyNumberList.append(var)
else:
    deltaTime = datetime.datetime.now() - startTime
    print("The 1500 ugly number is {}\nTime consuming is {} ms".format(uglyNumberList[-1], deltaTime.total_seconds()*1000))
