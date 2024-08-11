import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut, createUserWithEmailAndPassword, signInWithEmailAndPassword } from "firebase/auth";

const firebaseConfig = {
    apiKey: "AIzaSyDDjgFxuMR4VAT4jjqULEnx6-WMpWOIdww",
    authDomain: "password-manager-dc165.firebaseapp.com",
    projectId: "password-manager-dc165",
    storageBucket: "password-manager-dc165.appspot.com",
    messagingSenderId: "397516901537",
    appId: "1:397516901537:web:c1983a924bea1ec5c934e0",
    measurementId: "G-24JY41XYXY"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const provider = new GoogleAuthProvider();

export { auth, provider, signInWithPopup, signOut, createUserWithEmailAndPassword, signInWithEmailAndPassword };
