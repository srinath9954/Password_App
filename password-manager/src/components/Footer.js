import React from 'react';
import { Box, Typography, IconButton } from '@mui/material';
import { GitHub, LinkedIn, Instagram } from '@mui/icons-material';

const Footer = () => {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 2,
        backgroundColor: '#f5f5f5',
        color: '#333',
        mt: 1,
      }}
    >
      <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
        <IconButton
          component="a"
          href="https://github.com/srinath9954"
          target="_blank"
          sx={{ color: '#333' }}
        >
          <GitHub />
        </IconButton>
        <IconButton
          component="a"
          href="https://linkedin.com/in/srinath-p-8ab08b227/"
          target="_blank"
          sx={{ color: '#333' }}
        >
          <LinkedIn />
        </IconButton>
        <IconButton
          component="a"
          href="https://instagram.com/srinath9954"
          target="_blank"
          sx={{ color: '#333' }}
        >
          <Instagram />
        </IconButton>
      </Box>
      <Typography variant="body2" sx={{ fontStyle: 'italic' }}>
      &copy; 2024 Srinath P. All rights reserved.
      </Typography>
    </Box>
  );
};

export default Footer;
