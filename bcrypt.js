const bcrypt = require('bcrypt');
const saltRounds = 10;
const password = 'senha123';

bcrypt.hash(password,saltRounds, function(err,hash) {
    if(err) throw err;
    console.log(`Senha encriptada com sucesso ${hash}`);
    
    bcrypt.compare(password, hash, (err, result)=>{
        if(err) throw err;

        if(result){
            console.log("Senha valida!");

        }else{
            console.log("Senha invalida!");
        }
    });
});