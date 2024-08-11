import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Button, TextField, Container, Typography, Box, IconButton, Grid, Paper, CircularProgress } from '@mui/material';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { auth } from '../firebase';
import { styled } from '@mui/material/styles';

const ContainerStyled = styled(Container)(({ theme }) => ({
  padding: theme.spacing(4),
  backgroundColor: '#f5f5f5',
  borderRadius: '8px',
  boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)',
}));

const PaperStyled = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(2),
  marginBottom: theme.spacing(2),
}));

const PasswordText = styled('span')(({ theme }) => ({
  marginLeft: theme.spacing(1),
  fontFamily: 'monospace',
  wordBreak: 'break-all',
}));

const Dashboard = () => {
  const [website, setWebsite] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [passwords, setPasswords] = useState([]);
  const [showPassword, setShowPassword] = useState(false);
  const [timeoutId, setTimeoutId] = useState(null);
  const [loading, setLoading] = useState(true); // Add loading state

  useEffect(() => {
    const fetchPasswords = async () => {
      if (auth.currentUser) {
        const userId = auth.currentUser.uid;
        setLoading(true); // Set loading to true before fetching
        try {
          const response = await axios.get(`http://localhost:5000/get_passwords/${userId}`);
          setPasswords(response.data);
        } catch (error) {
          console.error('Error fetching passwords:', error);
        } finally {
          setLoading(false); // Set loading to false after fetching or error
        }
      }
    };

    fetchPasswords();
  }, []);

  useEffect(() => {
    const handleActivity = () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      const id = setTimeout(() => {
        handleSignOut();
      }, 5 * 60 * 1000);

      setTimeoutId(id);
    };

    window.addEventListener('mousemove', handleActivity);
    window.addEventListener('keypress', handleActivity);
    window.addEventListener('click', handleActivity);

    handleActivity();

    return () => {
      window.removeEventListener('mousemove', handleActivity);
      window.removeEventListener('keypress', handleActivity);
      window.removeEventListener('click', handleActivity);
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [timeoutId]);

  const handleAddPassword = async () => {
    if (auth.currentUser) {
      const userId = auth.currentUser.uid;
      try {
        await axios.post('http://localhost:5000/add_password', { website, username, password, user_id: userId });
        setWebsite('');
        setUsername('');
        setPassword('');
        setLoading(true); // Set loading to true before fetching updated passwords
        const response = await axios.get(`http://localhost:5000/get_passwords/${userId}`);
        setPasswords(response.data);
      } catch (error) {
        console.error('Error adding password:', error);
      } finally {
        setLoading(false); // Set loading to false after fetching or error
      }
    }
  };

  const handleDeletePassword = async (id) => {
    if (auth.currentUser) {
      try {
        await axios.delete('http://localhost:5000/delete_password', {
          data: { id }
        });
        setLoading(true); // Set loading to true before fetching updated passwords
        const userId = auth.currentUser.uid;
        const response = await axios.get(`http://localhost:5000/get_passwords/${userId}`);
        setPasswords(response.data);
      } catch (error) {
        console.error('Error deleting password:', error);
      } finally {
        setLoading(false); // Set loading to false after fetching or error
      }
    }
  };

  const handleTogglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleSignOut = async () => {
    try {
      await auth.signOut();
      window.location.href = '/';
    } catch (error) {
      console.error("Error signing out:", error);
    }
  };

  return (
    <ContainerStyled maxWidth="md">
      <Box>
        <Typography variant="h4" gutterBottom>Dashboard</Typography>
        {auth.currentUser && (
          <Typography variant="h6">Welcome, {auth.currentUser.displayName || auth.currentUser.email}</Typography>
        )}
        <Button variant="outlined" color="secondary" onClick={handleSignOut} sx={{ mt: 2 }}>
          Sign Out
        </Button>
        <PaperStyled>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <TextField
                label="Website"
                variant="outlined"
                margin="normal"
                fullWidth
                value={website}
                onChange={(e) => setWebsite(e.target.value)}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                label="Username"
                variant="outlined"
                margin="normal"
                fullWidth
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Password"
                type={showPassword ? 'text' : 'password'}
                variant="outlined"
                margin="normal"
                fullWidth
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                InputProps={{
                  endAdornment: (
                    <IconButton
                      aria-label="toggle password visibility"
                      onClick={handleTogglePasswordVisibility}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12}>
              <Button variant="contained" color="primary" onClick={handleAddPassword}>
                Add Password
              </Button>
            </Grid>
          </Grid>
        </PaperStyled>
        <Box mt={4}>
          <Typography variant="h6">Saved Passwords</Typography>
          {loading ? ( // Show loading spinner while loading
            <CircularProgress />
          ) : (
            passwords.map((pwd) => (
              <PaperStyled key={pwd._id}>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Typography variant="body1">Website: {pwd.website}</Typography>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="body1">Username: {pwd.username}</Typography>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="body1">
                      Password:
                      <PasswordText>
                        {showPassword ? pwd.password : '•••••••••••'}
                      </PasswordText>
                      <IconButton
                        aria-label="toggle password visibility"
                        onClick={handleTogglePasswordVisibility}
                        edge="end"
                        sx={{ ml: 1 }}
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Button
                      variant="outlined"
                      color="error"
                      onClick={() => handleDeletePassword(pwd._id)}
                    >
                      Delete
                    </Button>
                  </Grid>
                </Grid>
              </PaperStyled>
            ))
          )}
        </Box>
      </Box>
    </ContainerStyled>
  );
};

export default Dashboard;