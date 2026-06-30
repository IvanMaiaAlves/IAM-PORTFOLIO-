import json
import os

def load_matrix():
    """Carrega a matriz RBAC do arquivo JSON."""
    if not os.path.exists('rbac_matrix.json'):
        print("Erro: Arquivo rbac_matrix.json não encontrado!")
        return None
    with open('rbac_matrix.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def authorize(role, permission, matrix):
    """Valida se a role possui a permissão necessária."""
    roles = matrix.get("roles", {})
    
    if role not in roles:
        return False, f"Acesso Negado: A role '{role}' não existe no sistema."
    
    allowed_permissions = roles[role].get("permissions", [])
    
    if permission in allowed_permissions:
        return True, f"Acesso Permitido: Usuário com role '{role}' executou a ação '{permission}' com sucesso!"
    else:
        return False, f"Acesso Negado: A role '{role}' não tem permissão para '{permission}'."

def run_simulation():
    matrix = load_matrix()
    if not matrix:
        return

    print("=== SIMULADOR DE MATRIZ DE ACESSOS (RBAC) ===")
    
    # Lista as funções disponíveis para o teste
    print(f"Roles disponíveis: {', '.join(matrix['roles'].keys())}")
    print(f"Recursos do sistema: {', '.join(matrix['resources'])}\n")

    # Teste 1: Um analista tentando apenas ler (Deve ser permitido)
    print("--- Teste 1: Analista tentando ler dados ---")
    success, message = authorize("analyst", "read", matrix)
    print(f"Resultado: {message}\n")

    # Teste 2: Um analista tentando deletar algo (Deve ser negado)
    print("--- Teste 2: Analista tentando deletar dados ---")
    success, message = authorize("analyst", "delete", matrix)
    print(f"Resultado: {message}\n")

    # Teste 3: Um administrador gerenciando usuários (Deve ser permitido)
    print("--- Teste 3: Admin tentando gerenciar usuários ---")
    success, message = authorize("admin", "manage_users", matrix)
    print(f"Resultado: {message}\n")

if __name__ == "__main__":
    run_simulation()