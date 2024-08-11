import React from 'react';
import { AppBar, Toolbar, Typography, IconButton, Container } from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';

const Navbar = () => {
  return (
    <AppBar position="static" sx={{ backgroundColor: '#2c3e50' }}>
      <Container maxWidth="lg">
        <Toolbar disableGutters>
          <IconButton edge="start" color="inherit" aria-label="logo" sx={{ mr: 2 }}>
            <LockIcon />
          </IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontWeight: 'bold' }}>
            CipherSafe
          </Typography>
          <Typography variant="body2" sx={{ fontStyle: 'italic' }}>
      &copy; 2024 Srinath P. All rights reserved.
      </Typography>
        </Toolbar>
      </Container>
    </AppBar>
  );
};

export default Navbar;
