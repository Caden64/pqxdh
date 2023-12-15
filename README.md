# A basic example pqxdh implementation that should NOT be used 


 Revision 2 checklist
 
## PreKey Bundle (Bob)

- [x] Bob's curve identity key IK
- [x] Bob's signed curve prekey key spk (Does not need an identifier because there is only one key)
- [x] Bob's signature on the curve prekey SIG(IKSPK)
- [x] Bob's signed last-resort pqkem prekey (Does not need other pqkem keys because there is only one key)
- [x] Bob's Signature on the pqkem prekey
- [x] Bob's Onetime curve prekey
- [ ] Use Prekey Bundle

## Receive PreKey Bundle (Alice)

- [ ] Receive Bob's Prekey Bundle
- [ ] Verify Bob's Signature
- [ ] Generate pqkem encapsulated shared secret
- [ ] Generate DH1
- [ ] Generate DH2
- [ ] Generate DH3
- [ ] Generate DH4
- [ ] Calculate SK
- [ ] Calculate AD (Adding Bobs PQPK for additional security)
- [ ] Use Initial Message

## Receive the initial message (Bob)

- [ ] Decapsulate pqkem shared secret
- [ ] Do DH1 - DH4
- [ ] Calculate SK
- [ ] Calculate AD

## My addition (Bob)

- [ ] Send user made message to ALice

## My addition pt. 2 (Alice)

- [ ] Receive and decode message from Bob
