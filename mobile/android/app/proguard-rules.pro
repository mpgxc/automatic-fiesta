# Regras do R8 para o build de release.
#
# Este arquivo é referenciado por build.gradle.kts desde sempre, mas nunca
# existiu — o CI só rodava `assembleDebug`, então ninguém percebeu. Um
# `proguardFiles` apontando para arquivo inexistente derruba a task de release.
#
# É curto de propósito, e a razão importa: a serialização do protocolo é
# org.json escrita à mão, campo a campo (ver PhoneAuthClient.kt). Não existe
# classe de modelo cujo nome o R8 possa renomear e assim quebrar o formato de
# fio — que é a causa número um de "passa em debug e quebra em release".
#
# As bibliotecas (biometric, camera, ml kit, compose) trazem suas próprias
# consumer rules dentro dos AARs. Repeti-las aqui criaria duplicação que
# apodrece silenciosamente quando elas mudam de versão.

# Sem isto, um stack trace de produção vira lixo: os números de linha somem e o
# relatório aponta para lugar nenhum. O mapping.txt continua sendo o que
# desofusca os nomes.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# `Decision` atravessa a fronteira do wire pelo campo `wire`, não pelo nome da
# constante, então o R8 poderia renomeá-la sem consequência. Mantido mesmo
# assim: o dia em que alguém escrever `Decision.valueOf(...)` a partir de texto
# recebido, a falha seria em runtime, no aparelho do usuário, aprovando ou
# negando um pedido de sudo. Barato demais para deixar em aberto.
-keepclassmembers enum dev.phoneauth.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
