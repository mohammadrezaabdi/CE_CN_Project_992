# Computer Networks Project

Members:

- MohammadReza Abdi     `reza_abdi20@yahoo.com`
- Arshia Akhavan        `letmemakenewone@gmail.com`
- Amirmahdi Namjoo      `amirm137878@gmail.com`

-----

P2P Protocol with Chat Application that handles the Node as a binary tree.

### Quick Start

- Run manager.py using `python manager.py`.
- Run each node using `python client.py`.

`python manager.py` will run manager on `MANAGER_PORT` defined in `constants.py`. It will act as the handshaking server
that will introduce the parent to the recently added node (or inform the first node that it has no parent).

