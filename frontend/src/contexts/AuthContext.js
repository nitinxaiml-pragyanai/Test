import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tokens, setTokens] = useState({
    access: localStorage.getItem('access_token'),
    refresh: localStorage.getItem('refresh_token')
  });

  const logout = useCallback(() => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setTokens({ access: null, refresh: null });
    setUser(null);
  }, []);

  const refreshAccessToken = useCallback(async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) return null;

    try {
      const response = await axios.post(`${API}/auth/refresh`, {}, {
        headers: { Authorization: `Bearer ${refreshToken}` }
      });
      const newAccessToken = response.data.access_token;
      localStorage.setItem('access_token', newAccessToken);
      setTokens(prev => ({ ...prev, access: newAccessToken }));
      return newAccessToken;
    } catch (error) {
      logout();
      return null;
    }
  }, [logout]);

  const fetchUser = useCallback(async () => {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
      setLoading(false);
      return;
    }

    try {
      const response = await axios.get(`${API}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      setUser(response.data);
    } catch (error) {
      if (error.response?.status === 401) {
        const newToken = await refreshAccessToken();
        if (newToken) {
          try {
            const response = await axios.get(`${API}/auth/me`, {
              headers: { Authorization: `Bearer ${newToken}` }
            });
            setUser(response.data);
          } catch {
            logout();
          }
        }
      } else {
        logout();
      }
    } finally {
      setLoading(false);
    }
  }, [refreshAccessToken, logout]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = async (gateCode, username, password) => {
    const response = await axios.post(`${API}/auth/login`, {
      gate_code: gateCode,
      username,
      password
    });
    
    const { access_token, refresh_token, user: userData } = response.data;
    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);
    setTokens({ access: access_token, refresh: refresh_token });
    setUser(userData);
    return userData;
  };

  const getAuthHeader = useCallback(() => {
    const token = localStorage.getItem('access_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  }, []);

  const value = {
    user,
    loading,
    login,
    logout,
    getAuthHeader,
    refreshAccessToken,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
