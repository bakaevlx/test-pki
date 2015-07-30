
del *.cer
del *.jks


REM CA 1

keytool -genkeypair -alias ca1 -keyalg RSA -keysize 2048 -validity 1095 -dname "cn=CA1" -keystore ca1.jks -keypass welcome1 -storepass welcome1

keytool -list -keystore ca1.jks -storepass welcome1

keytool -export -alias ca1 -keystore ca1.jks -rfc -file ca1.cer -storepass welcome1



REM CA 2

keytool -genkeypair -alias ca2 -keyalg RSA -keysize 2048 -validity 1095 -dname "cn=CA2" -keystore ca2.jks -keypass welcome1 -storepass welcome1

keytool -list -keystore ca2.jks -storepass welcome1

keytool -export -alias ca2 -keystore ca2.jks -rfc -file ca2.cer -storepass welcome1




REM Issuing CA 1


keytool -genkeypair -alias issuing_ca1_1 -keyalg RSA -keysize 2048 -validity 1095 -dname "cn=IssuingCA1_1" -keystore issuing_ca1_1.jks -keypass welcome1 -storepass welcome1

REM trust CA cert 

keytool -import -alias ca1 -file ca1.cer -keystore issuing_ca1_1.jks -storepass welcome1ome1 -storepass welcome1 -noprompt -trustcacerts

keytool -certreq -alias issuing_ca1_1 -file issuing_ca1_1.csr -keystore issuing_ca1_1.jks -dname "cn=IssuingCA1_1" -storepass welcome1 -keypass welcome1

keytool -printcertreq -file issuing_ca1_1.csr

keytool -gencert -infile issuing_ca1_1.csr -outfile issuing_ca1_1.cer -rfc -validity 1095 -alias ca1 -keystore ca1.jks -keypass welcome1 -storepass welcome1 

keytool -importcert -alias issuing_ca1_1 -file issuing_ca1_1.cer -keystore issuing_ca1_1.jks -keypass welcome1 -storepass welcome1

keytool -list -v -keystore issuing_ca1_1.jks -storepass welcome1









