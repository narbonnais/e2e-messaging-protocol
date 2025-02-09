from repository.interfaces import MessageRepositoryInterface


class MockMessageRepository(MessageRepositoryInterface):
    def __init__(self):
        self.messages = []
        self.pulled_messages = []

    def store_message(
            self,
            recipient_pub,
            ciphertext,
            sender_pub,
            signature,
            nonce):
        self.messages.append(
            (recipient_pub, ciphertext, sender_pub, signature, nonce))
        return True

    def pull_messages(self, recipient_pub):
        messages = [m for m in self.messages if m[0] == recipient_pub]
        self.pulled_messages.extend(messages)
        self.messages = [m for m in self.messages if m[0] != recipient_pub]
        return messages

    # ... implement other methods ...
