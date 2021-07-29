# 判断一棵树是否是搜索二叉树。

class DoubleLinkedList:
    class Node:
        def __init__(self, data):
            self._data = data
            self._next = None
            self._pre = None

    def __init__(self):
        self.__head = DoubleLinkedList.Node("__head")
        self.__tail = DoubleLinkedList.Node("__tail")
        self.__head._next = self.__tail
        self.__tail._pre = self.__head

    def append(self, data):
        node = DoubleLinkedList.Node(data)
        self.__tail._pre._next = node
        node._pre = self.__tail._pre
        self.__tail._pre = node
        node._next = self.__tail

    def remove(self, data):
        node = self.__head
        while node != self.__tail:
            if node._data == data:
                node._pre._next = node._next
                node._next._pre = node._pre
                break
            node = node._next

    def pop(self):
        node = self.__tail._pre
        if node != self.__head:
            node._pre._next = node._next
            node._next._pre = node._pre
            node._next = None
            node._pre = None
            return node._data
        return None

    def is_empty(self) -> bool:
        return self.__head._next == self.__tail

    def iternodes(self) -> None:
        node = self.__head._next
        while node != self.__tail:
            yield node._data
            node = node._next

    def add_last(self, data: object) -> None:
        self.append(data)

    def poll_first(self):
        node = self.__head._next
        if node != self.__tail:
            self.__head._next = node._next
            node._next._pre = self.__head
            node._next = None
            node._pre = None
            return node._data
        return None

    def poll_last(self):
        return self.pop()

    def peek_first(self):
        node = self.__head._next
        if node != self.__tail:
            return node._data
        return None

    def peek_last(self):
        node = self.__tail._pre
        if node != self.__head:
            return node._data
        return None


class Stack:
    def __init__(self):
        self.__dlnklst = DoubleLinkedList()

    def pop(self):
        return self.__dlnklst.pop()

    def add(self, data):
        self.__dlnklst.append(data)

    def push(self, data):
        return self.__dlnklst.append(data)

    def peek(self):
        return self.__dlnklst.peek_last()

    def poll(self):
        return self.__dlnklst.poll_last()

    def is_empty(self):
        return self.__dlnklst.is_empty()

class Node:
    def __init__(self, data):
        self.__data = data
        self.__left = None
        self.__right = None

    @property
    def data(self):
        return self.__data

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

def is_bst_recur(head, pre=None):

    if not head:
        return True

    cur = head

    if not is_bst_recur(cur.left, pre):
        return False

    if pre and pre.data > cur.data:
        return False

    pre = cur

    return is_bst_recur(cur.right, pre)


def is_bst_unrecur(head):

    if not head:
        return

    stack = Stack()
    pre = None

    while not stack.is_empty() or head:
        if head:
            stack.add(head)
            head = head.left
        else:
            head = stack.pop()

            if pre and pre.data > head.data:
                return False
            pre = head
            head = head.right
    else:
        return True


if __name__ == "__main__":
    # BST
    head1 = Node(9)
    head1.left = Node(8)
    head1.right = Node(10)
    head1.left.left = Node(7)
    head1.left.right = Node(9)
    head1.right.left = Node(9)
    head1.right.right = Node(11)

    print(is_bst_recur(head1))  # True
    print(is_bst_unrecur(head1)) # True

    # Not BST
    head2 = Node(9)
    head2.left = Node(8)
    head2.right = Node(1)
    head2.left.left = Node(7)
    head2.left.right = Node(9)
    head2.right.left = Node(9)
    head2.right.right = Node(11)

    print(is_bst_recur(head2))  # False
    print(is_bst_unrecur(head2)) # False
