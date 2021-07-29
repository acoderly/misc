# 小和问题：在一个数组中，每一个数左边比当前数小的数累加起来，叫做这个数组的小和。求一个数组的小和。
# 例子[1, 3, 4, 6, 5]
# 1左边比1小的数，没有
# 3左边比3小的数，1；
# 4左边比4小的数，1，3；
# 6左边比6小的数，1，3，4；
# 5左边比5小的数，1，3，4；
# 所以小和为1+1+3+1+3+4+1+3+4=21

import random


def get_little_sum(array: list) -> int:
    def merge(array: list, left: int, middle: int, right: int) -> int:
        left_index = left
        right_index = middle + 1
        array_help = [0] * (right - left + 1)
        index = 0
        little_sum = 0
        while left_index <= middle and right_index <= right:
            if array[left_index] < array[right_index]:
                # 合并过程中出现左区数字x小于右区数字y，一次性榨取x对总体小和的贡献
                little_sum += (array[left_index] * (right - right_index + 1))

                array_help[index] = array[left_index]
                index, left_index = index + 1, left_index + 1

            else:
                array_help[index] = array[right_index]
                index, right_index = index + 1, right_index + 1

        while left_index <= middle:
            array_help[index] = array[left_index]
            index, left_index = index + 1, left_index + 1

        while right_index <= right:
            array_help[index] = array[right_index]
            index, right_index = index + 1, right_index + 1

        for i in range(len(array_help)):
            array[left + i] = array_help[i]
        return little_sum

    def merge_sort(array: list, left: int, right: int) -> int:
        if left == right:
            return 0
        mid = left + ((right - left) >> 1)
        left_little_sum = merge_sort(array, left, mid)
        right_little_sum = merge_sort(array, mid + 1, right)
        ret = merge(array, left, mid, right)
        return left_little_sum + right_little_sum + ret

    return merge_sort(array, 0, len(array) - 1)


def normal_method(lst: list) -> int:
    little_sum = 0
    for i in range(len(lst)):
        for j in range(i):
            if lst[j] < lst[i]:
                little_sum += lst[j]
    return little_sum


# Test
max_value = 100
max_length = 100
max_round = 100
array = [random.randint(-max_value, max_value) for i in range(max_length)]

for i in range(max_round):
    corr_answer = normal_method(array)
    little_sum = get_little_sum(array)
    if little_sum != corr_answer:
        print("Fucked.")
else:
    print("Success")
