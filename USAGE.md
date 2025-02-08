# Secure Messenger Usage Guide

A guide for using this web-based end-to-end encrypted messaging system.

## Starting the Servers

### Start Message Server
```bash
python -m src.server.runtime
```

### Start Client Web Interface
```bash
python -m src.client.web
```
Access the client interface at: http://127.0.0.1:8000

### Start Server Dashboard
```bash
python -m src.server.web
```
Access the server dashboard at: http://127.0.0.1:8001

## Using the Client Interface

### Key Management

1. Generate Keys
   - Enter your identifier (e.g., "alice") in the "Identifier" field
   - Click "Generate Key Pair"
   - This creates your public and private keys in the `.data` directory

2. Import Public Keys
   - Enter the other user's identifier (e.g., "bob") in "Import Public Key for"
   - Paste their public key PEM content into the textarea
   - Click "Import Public Key"

3. View Keys
   - Click "View My Keys" to see your available keys
   - You can see which users' public keys you have imported

### Sending Messages

1. Enter message details:
   - Your ID (sender): Your identifier (e.g., "alice")
   - Recipient ID: The recipient's identifier (e.g., "bob")
   - Message Text: Type your message in the textarea
   
2. Click "Send" to encrypt and send the message

### Retrieving Messages

1. Enter your ID in the "Pull Messages" section
2. Click "Pull" to check for and decrypt your messages
3. Decrypted messages will appear in the messages area

## Using the Server Dashboard

### Metrics View
- View current message counts
- Monitor message queue status
- Check when messages were last cleaned up

### Live Log
- Monitor server activity in real-time
- Track message delivery status
- View any system errors or warnings

## Security Notes

1. Private Key Security
   - Never share or expose your private key
   - Keep your `.data` directory secure
   - Use appropriate file permissions

2. Message Security
   - End-to-end encryption using RSA-2048
   - Messages are signed by the sender
   - Server only stores encrypted data

3. Data Retention
   - Messages auto-delete after 7 days
   - Pulled messages move to separate storage
   - Regular cleanup of old messages

4. Network Security
   - Use firewall rules for server access
   - Consider TLS for production use
   - Monitor server logs regularly

## Troubleshooting

1. Connection Issues
   - Verify all three servers are running
   - Check browser console for errors
   - Ensure ports 8000, 8001, and 50000 are available

2. Key Problems
   - Ensure proper key format when importing
   - Check key permissions in `.data` directory
   - Verify correct identifiers are being used

3. Message Issues
   - Confirm recipient's public key is imported
   - Check server dashboard for errors
   - Verify message encryption/decryption