import React from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import { auth } from './firebase';
import SignIn from './components/SignIn';
import NavBar from './components/Navbar';
import Footer from './components/Footer';

function App() {
  const [user, setUser] = React.useState(null);

  React.useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged(setUser);
    return () => unsubscribe();
  }, []);

  return (
    <Router>
      <NavBar />
      <Routes>
        <Route path="/SignIn" element={user ? <Navigate to="/dashboard" /> : <SignIn />} />
        <Route path="/dashboard" element={user ? <Dashboard /> : <Navigate to="/SignIn" />} />
        <Route path="/" element={<Navigate to="/SignIn" />} />
      </Routes>
      <Footer />
    </Router>
  );
}

export default App;
