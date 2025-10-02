## Trabalho Segurança

Antes de executar o codigo, voce deve intalar o gerenciador de pacotes `uv`:

```bash
wget -qO- https://astral.sh/uv/install.sh | sh
```

Com ele instalado, coloque o diretório contendo o binário dele no seu PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Depois, recarregue o shell:

```bash
source ~/.bashrc
```

Verifique a instalação:

```bash
uv --version
```

Sincronize os pacotes:

```bash
uv sync
```

Em uma instância do seu terminal, execute o servidor:

```bash
uv run server.py
```

Em outra instância do seu terminal, execute o client:

```bash
uv run client.py
```