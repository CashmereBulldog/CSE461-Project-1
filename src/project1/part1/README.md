# CSE461-Project

Group Members:
- Michael Christensen - mchris02
- Daniela Berreth     - danieb36
- Reed Hamilton       - rhamilt

Python Version - 3.12

## Part 1
### The sequence of server secrets that were received by your client program
With the last 3 digits of the student id of '857' we got the following output:
```
Final list of secrets:
    Secret A: 34
    Secret B: 16
    Secret C: 1
    Secret D: 49
```

### Instructions on setting up client
To run a client that tries to connect to the attu server (attu2.cs.washington.edu), simply run either of the following commands:
```
    python client.py
    python client.py "attu2.cs.washington.edu"
```
For other addresses, you can specify the `address` by running the command
```
    python client.py <address>
```