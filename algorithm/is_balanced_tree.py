# 使用递归方式判断一颗二叉树是否为平衡二叉树。

class Node:
    def __init__(self, data):
        self.__data = data
        self.__left = None
        self.__right = None

    @property
    def left(self):
        return self.__left

    @left.setter
    def left(self, node):
        self.__left = node

    @property
    def right(self):
        return self.__right

    @right.setter
    def right(self, node):
        self.__right = node

class ReturnData:
    def __init__(self, isbalanced, height):
        self.__isbalanced = isbalanced
        self.__height = height

    @property
    def isbalanced(self):
        return self.__isbalanced

    @isbalanced.setter
    def isbalanced(self, isbalanced):
        self.__isbalanced = isbalanced

    @property
    def height(self):
        return self.__height

    @height.setter
    def height(self, height):
        self.__height = height

def is_balanced_tree(head):
    def process(head):
        if not head:
            return ReturnData(True, 0)

        left_result = process(head.left)
        right_result = process(head.right)

        if not left_result.isbalanced or not right_result.isbalanced:
            return ReturnData(False, max(left_result.height, right_result.height) + 1)

        if abs(left_result.height - right_result.height) > 1:
            return ReturnData(False, max(left_result.height, right_result.height) + 1)
        else:
            return ReturnData(True, max(left_result.height, right_result.height) + 1)

    return process(head).isbalanced


if __name__ == "__main__":
    # Balanced Tree
    head1 = Node(1)
    head1.left = Node(2)
    head1.right = Node(3)
    head1.left.left = Node(4)
    head1.left.right = Node(5)

    print(is_balanced_tree(head1)) # True

    # Not Balanced Tree
    head2 = Node(1)
    head2.left = Node(2)
    head2.left.left = Node(4)
    head2.left.right = Node(5)

    print(is_balanced_tree(head2)) #False
