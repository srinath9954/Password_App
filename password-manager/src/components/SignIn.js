import React, { useState } from 'react';
import { signInWithPopup, provider, auth, signInWithEmailAndPassword, createUserWithEmailAndPassword } from '../firebase';
import { Button, TextField, Container, Typography, Box, IconButton, InputAdornment, Paper } from '@mui/material';
import { Google as GoogleIcon, Visibility, VisibilityOff } from '@mui/icons-material';

const SignIn = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSignUp, setIsSignUp] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleAuth = async () => {
    try {
      if (isSignUp) {
        await createUserWithEmailAndPassword(auth, email, password);
      } else {
        await signInWithEmailAndPassword(auth, email, password);
      }
    } catch (error) {
      console.error("Error signing in:", error.message);
    }
  };

  const handleGoogleSignIn = async () => {
    try {
      await signInWithPopup(auth, provider);
    } catch (error) {
      console.error("Error signing in with Google:", error.message);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  return (
    <Container maxWidth="xs" sx={{ marginTop: 8 }}>
      <Paper elevation={3} sx={{ padding: 4, borderRadius: 3, backgroundColor: '#f7f7f7' }}>
        <Box display="flex" flexDirection="column" alignItems="center">
          <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', color: '#2c3e50' }}>
            {isSignUp ? 'Create Account' : 'Welcome Back'}
          </Typography>
          <TextField
            label="Email"
            variant="outlined"
            margin="normal"
            fullWidth
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            sx={{ backgroundColor: 'white' }}
          />
          <TextField
            label="Password"
            type={showPassword ? 'text' : 'password'}
            variant="outlined"
            margin="normal"
            fullWidth
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            sx={{ backgroundColor: 'white' }}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton onClick={togglePasswordVisibility}>
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
          <Button
            variant="contained"
            onClick={handleAuth}
            fullWidth
            sx={{ marginTop: 2, padding: 1.5, fontWeight: 'bold',backgroundColor: '#2c3e50',  // Custom background color
              '&:hover': {
                backgroundColor: '#34495e',  // Darker shade for hover effect
              }, }}
          >
            {isSignUp ? 'Sign Up' : 'Sign In'}
          </Button>
          <Button
            variant="outlined"
            color="secondary"
            startIcon={<GoogleIcon />}
            onClick={handleGoogleSignIn}
            fullWidth
            sx={{ marginTop: 2, padding: 1.5 }}
          >
            Sign In/Sign Up with Google
          </Button>
          <Button
            onClick={() => setIsSignUp(!isSignUp)}
            sx={{ marginTop: 2, textTransform: 'none',color:'#2c3e50',fontWeight: 'bold' }}
          >
            {isSignUp ? 'Already have an account? Sign In' : 'Need an account? Sign Up'}
          </Button>
        </Box>
        <Typography variant="caption" color="textSecondary" align="center" sx={{ mt: 2 }}>
  Developed by Srinath
</Typography>

      </Paper>
    </Container>
  );
};

export default SignIn;
