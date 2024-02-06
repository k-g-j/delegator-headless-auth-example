import logo from './logo.svg';
import DeleGatorImage from './DeleGator.png';
import './App.css';
import './index.css';
import {useState} from 'react';
import {client, parsers, server, utils} from 'https://unpkg.com/@passwordless-id/webauthn@1.2.6/dist/webauthn.min.js';
import { 
  randomChallenge, 
  toBuffer, 
  parseBuffer, 
  isBase64url, 
  toBase64url, 
  parseBase64url, 
  sha256, 
  bufferToHex, 
  concatenateBuffers, 
  hexToBase64,
  base64ToBase64Url,
  getPublicKeyCoordinates,
  getSignatureComponents,
  base64UrlToHex,
  getPublicKeyFromBytes,
  signP256,
  signUsingPrivateKey,
  signLikeSim
} from './utils.js'

function App() {
  const [username, setUsername] = useState('');
  const [userOpHash, setUserOpHash] = useState('');
  const [registerationOutput, setRegisterationOutput] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [challengeHash, setChallengeHash] = useState('');
  const [keyId, setKeyId] = useState('');
  const [authData, setAuthData] = useState('');
  const [signature, setSignature] = useState('');
  const [rs, setRS] = useState('');
  const [authenticatorDataHash, setAuthenticatorDataHash] = useState('');
  const [newKeySignature, setNewKeySignature] = useState('');
  const [keyUsername, setKeyUsername] = useState('');

  const register = async () => {
    try {
      
      let res = await client.register(username, randomChallenge());
      
      const parsedRegisteration = parsers.parseRegistration(res);

      setRegisterationOutput(parsedRegisteration);
      window.localStorage.setItem(username, parsedRegisteration.credential.id)

      const publicKey = await getPublicKeyFromBytes(parsedRegisteration.credential.publicKey);

      setPublicKey(publicKey);
      
      setKeyId(parsedRegisteration.credential.id);
      console.log(keyId);
      
    }
    catch(e) {
      alert(e);
    }

  };

  const authenticate = async () => {
    const base64EncodedUserOp = hexToBase64(userOpHash);
    const base64UrlUserOp = base64ToBase64Url(base64EncodedUserOp);
    const credId =  window.localStorage.getItem(username);
    
    const authData = await client.authenticate([credId], base64UrlUserOp)
    console.log(JSON.stringify(authData));


    const parsedAuthData = parsers.parseAuthentication(authData);
    
    
    setAuthData(parsedAuthData);

    const challengeHash = base64UrlToHex(parsedAuthData.client.challenge);

    setChallengeHash(challengeHash);

    setAuthenticatorDataHash(base64UrlToHex(authData.authenticatorData));  

    setSignature(parsedAuthData.signature);
    
    const rsArray = getSignatureComponents(parsedAuthData.signature);
    const rsJSON = {
      "r": rsArray[0],
      "s": rsArray[1],
    }
    setRS(rsJSON);
  };

  const sign = async() => {
    const sigObject = await signP256(userOpHash);
    console.log("subObject:  ",sigObject)
    setNewKeySignature(sigObject);    
    window.localStorage.setItem(keyUsername, JSON.stringify(sigObject.priv));
  }

  const signWithKey = async() => {

    const privKey = window.localStorage.getItem(keyUsername);
    console.log("private Key", privKey);
    const sigObject = await signUsingPrivateKey(JSON.parse(privKey), userOpHash);
    setNewKeySignature(sigObject);

  }
  // const getRS = async () => {
  //   const rs = getSignatureComponents(signature);
  // }
  return (
    <div className="App">
      <header className="App-header">
        <img src={DeleGatorImage} className='App-logo'/>
        <input 
        type="text" 
        value={username} 
        onChange={e => setUsername(e.target.value)} 
        placeholder="Enter username" 
        />
        <button onClick={register}>Register</button>
        <h4>
          Registeration Data
        </h4>
        <textarea
        value={JSON.stringify(registerationOutput, null, 2)} 
        readOnly 
        style={{ width: '40%', height: '200px', marginTop: '5px' }} 
        />
        <h4>
          Public Key
        </h4>
        <textarea
          value={JSON.stringify(publicKey, null, 2)} 
          readOnly 
          style={{ width: '40%', height: '100px', marginTop: '5px' }} 
        />
        <h3>Authenticate</h3>
        <input 
        type="text" 
        value={userOpHash} 
        onChange={e => setUserOpHash(e.target.value)} 
        placeholder="Enter userOpHash" 
        />
        <button onClick={authenticate}>Authenticate</button>
         <h4>
          Authenticator Data
        </h4>
        <textarea
          value={JSON.stringify(authData, null, 2)} 
          readOnly 
          style={{ width: '40%', height: '200px', marginTop: '5px' }} 
        />
        <h4>
          Challenge Hash
        </h4>
        <textarea
          value={challengeHash} 
          readOnly 
          style={{ width: '40%', height: '50px', marginTop: '5px' }} 
        />
        <h4>
          Authenticator Data (Hex)
        </h4>
        <textarea
          value={authenticatorDataHash} 
          readOnly 
          style={{ width: '40%', height: '50px', marginTop: '5px' }} 
        />
        <h4>
          RS - Sig
        </h4>
        <textarea
          value={JSON.stringify(rs, null, 2)} 
          readOnly 
          style={{ width: '40%', height: '50px', marginTop: '5px' }} 
        />
        <input 
        type="text" 
        value={keyUsername} 
        onChange={e => setKeyUsername(e.target.value)} 
        placeholder="Enter key username" 
        />
         <button onClick={signWithKey}>sign with key</button>
         <h4>
          New KeyPair-Signature
        </h4>
        <textarea
          value={JSON.stringify(newKeySignature, null, 2)} 
          readOnly 
          style={{ width: '40%', height: '200px', marginTop: '5px' }} 
        />

        <button onClick={sign}>Generate</button>
         <h4>
          ----------
        </h4>
      </header>
      <footer className="footer">Footer</footer>
    </div>
  );
}

export default App;
