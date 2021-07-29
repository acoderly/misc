import random
number = random.randint(1,100)
print("number:{} binary:{} ".format(number,bin(number)))
count = 0
while number != 0:
    number,count = (number-1)&number, count + 1
else:
    print(count)
