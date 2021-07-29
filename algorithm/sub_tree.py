# 判断一个二叉树T1是否是另一颗二叉树T2的子树。(T2>T1)
#
# 要求：时间复杂度O(N)，空间复杂度O(1)
#
# 1.morris遍历实现T1，T2的先序序列化。
#
# 2.kmp算法判断T1与T2的序列化结果(T2>T1)
#
# 　（1）如果seralize(T1)是seralize(T2)的子串，则T1是T2的子树
#
# 　（2）否则，T1不是T2的子树

class MyProperty:
    def __init__(self, get_attrib_func):
        self.get_attrib_func = get_attrib_func
        self.set_attrib_func = None

    def __set__(self, instance, value):
        if not self.set_attrib_func:
            raise AttributeError("can't set attribute")
        self.set_attrib_func(instance, value)

    def __get__(self, instance, owner):
        return self.get_attrib_func(instance)

    def setter(self, set_attrib_func):
        self.set_attrib_func = set_attrib_func
        return self


class Node:
    def __init__(self, value):
        self.value = value
        self.__left = None
        self.__right = None

    @MyProperty
    def left(self):
        return self.__left

    @left.setter
    def left(self, node):
        self.__left = node

    @MyProperty
    def right(self):
        return self.__right

    @right.setter
    def right(self, node):
        self.__right = node


def morris_pre_serialize(head):
    if not head:
        return
    string = []
    cur = head
    most_right = None
    while cur != None:
        most_right = cur.left
        if most_right != None:
            while most_right.right != None and most_right.right != cur:
                most_right = most_right.right

            if most_right.right == None:  # 第一次到达cur节点
                string.append("{}{}".format(cur.value, "_"))
                most_right.right = cur
                cur = cur.left
                continue
            else:
                most_right.right = None  # 第二次到达cur节点
                string.append("#_")

        else:
            string.append(str(cur.value) + "_")
            string.append("#_")
        cur = cur.right
    else:
        string.append("#_")

    return "".join(string)


def kmp(str_x, str_y):
    def __get_nexts(str_x):
        if str_x is None:
            return None

        length = len(str_x)
        if length == 1:
            return [-1]

        nexts = [0] * length
        nexts[0] = -1
        nexts[1] = 0
        i1, i2 = 2, 1
        while i1 < length:
            if str_x[i1 - 1] == str_x[nexts[i2]]:
                nexts[i1] = nexts[i2] + 1
                i2, i1 = i1, i1 + 1
            elif nexts[i2] != -1:
                i2 = nexts[i2]
            else:
                nexts[i1] = 0
                i2, i1 = i1, i1 + 1
        return nexts

    if str_x is None or str_y is None or len(str_y) < 1 or len(str_x) < len(str_y):
        return -1

    len_str_x, len_str_y = len(str_x), len(str_y)

    i1, i2 = 0, 0

    nexts = __get_nexts(str_y)

    while i1 < len_str_x and i2 < len_str_y:
        if str_x[i1] == str_y[i2]:
            i1, i2 = i1 + 1, i2 + 1
        elif nexts[i2] != -1:
            i2 = nexts[i2]
        else:
            i1 += 1
    return i1 - i2 if i2 == len_str_y else -1


def is_sub_tree(head1, head2):
    if head1 is None or head2 is None:
        return False

    str1 = morris_pre_serialize(head1)
    str2 = morris_pre_serialize(head2)

    str1, str2 = (str2, str1) if len(str1) < len(str2) else (str1, str2)

    ret = kmp(str1, str2)

    return True if ret != -1 else False


if __name__ == "__main__":
    tree_1 = Node(1)
    tree_1.left = Node(2)
    tree_1.right = Node(3)
    tree_1.left.left = Node(4)
    tree_1.left.right = Node(5)
    tree_1.right.left = Node(6)
    tree_1.right.right = Node(7)

    tree_2 = Node(3)
    tree_2.left = Node(6)
    tree_2.right = Node(7)
    tree_2.left.right = Node(8)
    # tree_2 is not tree_1's sub tree
    print(is_sub_tree(tree_2, tree_1))  # False
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    tree_3 = Node(3)
    tree_3.left = Node(6)
    tree_3.right = Node(7)
    # tree_3 is tree_1's sub tree
    print(is_sub_tree(tree_1, tree_3))  # True
