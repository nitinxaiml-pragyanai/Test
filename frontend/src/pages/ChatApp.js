import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger,
  DropdownMenuSeparator 
} from '@/components/ui/dropdown-menu';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  MessageCircle, Search, Send, Plus, Users, User, LogOut, 
  MoreVertical, Paperclip, Image, FileText, Reply, Trash2,
  Check, CheckCheck, X, Hash
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { io } from 'socket.io-client';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const SOCKET_URL = process.env.REACT_APP_BACKEND_URL;

const ChatApp = () => {
  const navigate = useNavigate();
  const { user, logout, getAuthHeader } = useAuth();
  const [chats, setChats] = useState([]);
  const [users, setUsers] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [typingUsers, setTypingUsers] = useState({});
  const [onlineUsers, setOnlineUsers] = useState(new Set());
  const [replyTo, setReplyTo] = useState(null);
  const [showNewChat, setShowNewChat] = useState(false);
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [groupName, setGroupName] = useState('');
  const [selectedMembers, setSelectedMembers] = useState([]);
  const messagesEndRef = useRef(null);
  const socketRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const fileInputRef = useRef(null);

  // Initialize Socket.IO
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;

    socketRef.current = io(SOCKET_URL, {
      auth: { token },
      transports: ['websocket', 'polling']
    });

    socketRef.current.on('connect', () => {
      console.log('Socket connected');
    });

    socketRef.current.on('new_message', (msg) => {
      setMessages(prev => {
        if (prev.some(m => m.id === msg.id || m.message_uuid === msg.message_uuid)) {
          return prev;
        }
        return [...prev, msg];
      });
      // Update chat list
      fetchChats();
    });

    socketRef.current.on('message_deleted', ({ message_id }) => {
      setMessages(prev => prev.filter(m => m.id !== message_id));
    });

    socketRef.current.on('user_typing', ({ chat_id, user_id, display_name }) => {
      if (chat_id === activeChat?.id) {
        setTypingUsers(prev => ({ ...prev, [user_id]: display_name }));
      }
    });

    socketRef.current.on('user_stop_typing', ({ chat_id, user_id }) => {
      setTypingUsers(prev => {
        const newState = { ...prev };
        delete newState[user_id];
        return newState;
      });
    });

    socketRef.current.on('user_online', ({ user_id }) => {
      setOnlineUsers(prev => new Set([...prev, user_id]));
    });

    socketRef.current.on('user_offline', ({ user_id }) => {
      setOnlineUsers(prev => {
        const newSet = new Set(prev);
        newSet.delete(user_id);
        return newSet;
      });
    });

    socketRef.current.on('force_logout', () => {
      toast.error('You have been logged out by admin');
      logout();
      navigate('/gate');
    });

    socketRef.current.on('message_read_update', ({ message_id, user_id }) => {
      setMessages(prev => prev.map(m => 
        m.id === message_id 
          ? { ...m, read_by: [...(m.read_by || []), user_id] }
          : m
      ));
    });

    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, [activeChat?.id, logout, navigate]);

  // Fetch initial data
  const fetchChats = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/chats`, { headers: getAuthHeader() });
      setChats(response.data);
    } catch (error) {
      console.error('Failed to fetch chats:', error);
    }
  }, [getAuthHeader]);

  const fetchUsers = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/users`, { headers: getAuthHeader() });
      setUsers(response.data);
      // Update online users
      const online = response.data.filter(u => u.online).map(u => u.id);
      setOnlineUsers(new Set(online));
    } catch (error) {
      console.error('Failed to fetch users:', error);
    }
  }, [getAuthHeader]);

  useEffect(() => {
    const init = async () => {
      await Promise.all([fetchChats(), fetchUsers()]);
      setLoading(false);
    };
    init();
  }, [fetchChats, fetchUsers]);

  // Fetch messages when active chat changes
  useEffect(() => {
    if (!activeChat) return;

    const fetchMessages = async () => {
      try {
        const response = await axios.get(`${API}/chats/${activeChat.id}/messages`, {
          headers: getAuthHeader()
        });
        setMessages(response.data);
        
        // Join socket room
        if (socketRef.current) {
          socketRef.current.emit('join_chat', { chat_id: activeChat.id });
        }
      } catch (error) {
        console.error('Failed to fetch messages:', error);
      }
    };

    fetchMessages();

    return () => {
      if (socketRef.current) {
        socketRef.current.emit('leave_chat', { chat_id: activeChat.id });
      }
    };
  }, [activeChat, getAuthHeader]);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Handle typing indicator
  const handleTyping = () => {
    if (!activeChat || !socketRef.current) return;

    socketRef.current.emit('typing', { chat_id: activeChat.id });

    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }

    typingTimeoutRef.current = setTimeout(() => {
      socketRef.current.emit('stop_typing', { chat_id: activeChat.id });
    }, 2000);
  };

  // Send message
  const handleSendMessage = async (e) => {
    e?.preventDefault();
    if (!newMessage.trim() || !activeChat || sending) return;

    const messageUuid = uuidv4();
    const content = newMessage.trim();
    setNewMessage('');
    setSending(true);

    // Optimistic update
    const optimisticMsg = {
      id: messageUuid,
      message_uuid: messageUuid,
      chat_id: activeChat.id,
      sender_id: user.id,
      sender_name: user.display_name,
      content,
      reply_to: replyTo?.id,
      created_at: new Date().toISOString(),
      pending: true
    };
    setMessages(prev => [...prev, optimisticMsg]);
    setReplyTo(null);

    try {
      const response = await axios.post(`${API}/chats/${activeChat.id}/messages`, {
        chat_id: activeChat.id,
        content,
        message_uuid: messageUuid,
        reply_to: replyTo?.id
      }, { headers: getAuthHeader() });

      // Update with server response
      setMessages(prev => prev.map(m => 
        m.message_uuid === messageUuid 
          ? { ...m, id: response.data.id, pending: false }
          : m
      ));
    } catch (error) {
      const message = error.response?.data?.detail || 'Failed to send message';
      toast.error(message);
      // Remove failed message
      setMessages(prev => prev.filter(m => m.message_uuid !== messageUuid));
    } finally {
      setSending(false);
    }
  };

  // Handle file upload
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file || !activeChat) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('message_uuid', uuidv4());

    try {
      await axios.post(`${API}/chats/${activeChat.id}/upload`, formData, {
        headers: { ...getAuthHeader(), 'Content-Type': 'multipart/form-data' }
      });
      toast.success('File uploaded');
    } catch (error) {
      toast.error('Failed to upload file');
    }

    e.target.value = '';
  };

  // Start new DM
  const handleStartDM = async (userId) => {
    try {
      const response = await axios.post(`${API}/dm/${userId}`, {}, { headers: getAuthHeader() });
      await fetchChats();
      const chat = chats.find(c => c.id === response.data.chat_id) || 
        { id: response.data.chat_id, type: 'dm' };
      setActiveChat(chat);
      setShowNewChat(false);
    } catch (error) {
      toast.error('Failed to start conversation');
    }
  };

  // Create group
  const handleCreateGroup = async () => {
    if (!groupName.trim() || selectedMembers.length === 0) {
      toast.error('Please enter a name and select members');
      return;
    }

    try {
      const response = await axios.post(`${API}/groups`, {
        name: groupName.trim(),
        member_ids: selectedMembers
      }, { headers: getAuthHeader() });

      await fetchChats();
      setActiveChat({ id: response.data.chat_id, type: 'group', name: groupName });
      setShowNewGroup(false);
      setGroupName('');
      setSelectedMembers([]);
      toast.success('Group created');
    } catch (error) {
      toast.error('Failed to create group');
    }
  };

  // Delete message
  const handleDeleteMessage = async (messageId, forEveryone = false) => {
    try {
      await axios.delete(`${API}/messages/${messageId}?for_everyone=${forEveryone}`, {
        headers: getAuthHeader()
      });
      setMessages(prev => prev.filter(m => m.id !== messageId));
      toast.success('Message deleted');
    } catch (error) {
      toast.error('Failed to delete message');
    }
  };

  // Handle logout
  const handleLogout = () => {
    logout();
    navigate('/gate');
  };

  // Filter chats by search
  const filteredChats = chats.filter(chat => {
    const name = chat.type === 'dm' 
      ? chat.other_user?.display_name 
      : chat.name;
    return name?.toLowerCase().includes(searchQuery.toLowerCase());
  });

  // Get chat display info
  const getChatInfo = (chat) => {
    if (chat.type === 'dm') {
      return {
        name: chat.other_user?.display_name || 'Unknown',
        avatar: chat.other_user?.display_name?.charAt(0) || '?',
        online: onlineUsers.has(chat.other_user?.id)
      };
    }
    return {
      name: chat.name || 'Group',
      avatar: chat.name?.charAt(0) || 'G',
      online: false
    };
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="w-8 h-8 border-2 border-black border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="h-screen flex bg-background" data-testid="chat-app">
      {/* Sidebar */}
      <div className="w-80 border-r border-border flex flex-col chat-sidebar">
        {/* Header */}
        <div className="p-4 border-b border-border/50">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-black rounded-xl flex items-center justify-center">
                <MessageCircle className="w-5 h-5 text-white" />
              </div>
              <span className="font-bold text-lg" style={{ fontFamily: 'Manrope, sans-serif' }}>
                ObsidianX
              </span>
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="rounded-full">
                  <MoreVertical className="w-5 h-5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuItem className="flex items-center gap-2">
                  <User className="w-4 h-4" />
                  <span>{user?.display_name}</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem 
                  data-testid="logout-btn"
                  onClick={handleLogout}
                  className="flex items-center gap-2 text-destructive"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Logout</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              data-testid="chat-search-input"
              type="text"
              placeholder="Search chats..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-10 pl-10 bg-secondary/50 border-transparent rounded-xl text-sm"
            />
          </div>
        </div>

        {/* New chat buttons */}
        <div className="p-3 flex gap-2">
          <Dialog open={showNewChat} onOpenChange={setShowNewChat}>
            <DialogTrigger asChild>
              <Button 
                data-testid="new-dm-btn"
                variant="secondary" 
                className="flex-1 h-9 rounded-xl text-sm"
              >
                <User className="w-4 h-4 mr-2" />
                New DM
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Start a conversation</DialogTitle>
              </DialogHeader>
              <ScrollArea className="h-64 mt-4">
                <div className="space-y-2">
                  {users.map((u) => (
                    <button
                      key={u.id}
                      data-testid={`dm-user-${u.id}`}
                      onClick={() => handleStartDM(u.id)}
                      className="w-full flex items-center gap-3 p-3 rounded-xl hover:bg-secondary transition-colors"
                    >
                      <div className="relative">
                        <Avatar className="w-10 h-10">
                          <AvatarFallback>{u.display_name?.charAt(0)}</AvatarFallback>
                        </Avatar>
                        {onlineUsers.has(u.id) && (
                          <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 rounded-full border-2 border-white" />
                        )}
                      </div>
                      <div className="text-left">
                        <p className="font-medium">{u.display_name}</p>
                        <p className="text-xs text-muted-foreground">@{u.username}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </ScrollArea>
            </DialogContent>
          </Dialog>

          <Dialog open={showNewGroup} onOpenChange={setShowNewGroup}>
            <DialogTrigger asChild>
              <Button 
                data-testid="new-group-btn"
                variant="secondary" 
                className="flex-1 h-9 rounded-xl text-sm"
              >
                <Users className="w-4 h-4 mr-2" />
                New Group
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create a group</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 mt-4">
                <Input
                  data-testid="group-name-input"
                  placeholder="Group name..."
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  className="h-12 rounded-xl"
                />
                <p className="text-sm text-muted-foreground">Select members:</p>
                <ScrollArea className="h-48">
                  <div className="space-y-2">
                    {users.map((u) => (
                      <button
                        key={u.id}
                        onClick={() => {
                          setSelectedMembers(prev => 
                            prev.includes(u.id)
                              ? prev.filter(id => id !== u.id)
                              : [...prev, u.id]
                          );
                        }}
                        className={`w-full flex items-center gap-3 p-3 rounded-xl transition-colors ${
                          selectedMembers.includes(u.id) ? 'bg-black text-white' : 'hover:bg-secondary'
                        }`}
                      >
                        <Avatar className="w-8 h-8">
                          <AvatarFallback className={selectedMembers.includes(u.id) ? 'bg-white/20 text-white' : ''}>
                            {u.display_name?.charAt(0)}
                          </AvatarFallback>
                        </Avatar>
                        <span className="font-medium">{u.display_name}</span>
                      </button>
                    ))}
                  </div>
                </ScrollArea>
                <Button
                  data-testid="create-group-btn"
                  onClick={handleCreateGroup}
                  className="w-full h-12 rounded-full"
                >
                  Create Group
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        {/* Chat list */}
        <ScrollArea className="flex-1">
          <div className="p-2 space-y-1">
            {filteredChats.map((chat) => {
              const info = getChatInfo(chat);
              return (
                <button
                  key={chat.id}
                  data-testid={`chat-item-${chat.id}`}
                  onClick={() => setActiveChat(chat)}
                  className={`w-full flex items-center gap-3 p-3 rounded-2xl transition-all ${
                    activeChat?.id === chat.id
                      ? 'bg-black text-white'
                      : 'hover:bg-secondary'
                  }`}
                >
                  <div className="relative">
                    <Avatar className="w-12 h-12">
                      <AvatarFallback className={activeChat?.id === chat.id ? 'bg-white/20 text-white' : 'bg-secondary'}>
                        {chat.type === 'main_group' ? <Hash className="w-5 h-5" /> : info.avatar}
                      </AvatarFallback>
                    </Avatar>
                    {info.online && (
                      <div className="absolute bottom-0 right-0 w-3.5 h-3.5 bg-green-500 rounded-full border-2 border-white" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0 text-left">
                    <div className="flex items-center justify-between">
                      <p className="font-medium truncate">
                        {chat.type === 'main_group' ? 'Class Group' : info.name}
                      </p>
                      {chat.unread_count > 0 && (
                        <span className="unread-badge ml-2">{chat.unread_count}</span>
                      )}
                    </div>
                    {chat.last_message && (
                      <p className={`text-sm truncate ${
                        activeChat?.id === chat.id ? 'text-white/70' : 'text-muted-foreground'
                      }`}>
                        {chat.last_message.content}
                      </p>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </ScrollArea>
      </div>

      {/* Chat area */}
      <div className="flex-1 flex flex-col">
        {activeChat ? (
          <>
            {/* Chat header */}
            <div className="h-16 px-6 border-b border-border flex items-center justify-between glass">
              <div className="flex items-center gap-3">
                <Avatar className="w-10 h-10">
                  <AvatarFallback>
                    {activeChat.type === 'main_group' 
                      ? <Hash className="w-5 h-5" />
                      : getChatInfo(activeChat).avatar
                    }
                  </AvatarFallback>
                </Avatar>
                <div>
                  <p className="font-medium" style={{ fontFamily: 'Manrope, sans-serif' }}>
                    {activeChat.type === 'main_group' ? 'Class Group' : getChatInfo(activeChat).name}
                  </p>
                  {Object.keys(typingUsers).length > 0 && (
                    <p className="text-xs text-[#007AFF]">
                      {Object.values(typingUsers).join(', ')} typing...
                    </p>
                  )}
                </div>
              </div>
            </div>

            {/* Messages */}
            <ScrollArea className="flex-1 p-6">
              <div className="space-y-4 max-w-3xl mx-auto">
                <AnimatePresence>
                  {messages.map((msg, idx) => {
                    const isMine = msg.sender_id === user?.id;
                    const showAvatar = !isMine && (idx === 0 || messages[idx - 1]?.sender_id !== msg.sender_id);
                    
                    return (
                      <motion.div
                        key={msg.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className={`flex items-end gap-2 ${isMine ? 'justify-end' : 'justify-start'}`}
                      >
                        {!isMine && showAvatar && (
                          <Avatar className="w-8 h-8">
                            <AvatarFallback className="text-xs">
                              {msg.sender_name?.charAt(0)}
                            </AvatarFallback>
                          </Avatar>
                        )}
                        {!isMine && !showAvatar && <div className="w-8" />}
                        
                        <div className={`group max-w-[70%] ${isMine ? 'items-end' : 'items-start'}`}>
                          {!isMine && showAvatar && (
                            <p className="text-xs text-muted-foreground mb-1 ml-1">
                              {msg.sender_name}
                            </p>
                          )}
                          
                          {msg.reply_to && (
                            <div className="text-xs bg-secondary/50 rounded-lg px-3 py-1.5 mb-1 border-l-2 border-muted-foreground">
                              Reply to message
                            </div>
                          )}
                          
                          <div className="flex items-end gap-2">
                            <div
                              data-testid={`message-${msg.id}`}
                              className={`relative px-4 py-2.5 ${
                                isMine ? 'message-bubble-sent' : 'message-bubble-received'
                              } ${msg.pending ? 'opacity-70' : ''}`}
                            >
                              {msg.attachment && (
                                <div className="mb-2">
                                  {msg.attachment.content_type?.startsWith('image/') ? (
                                    <img 
                                      src={`${process.env.REACT_APP_BACKEND_URL}${msg.attachment.url}`}
                                      alt={msg.attachment.filename}
                                      className="rounded-lg max-w-[200px]"
                                    />
                                  ) : (
                                    <a 
                                      href={`${process.env.REACT_APP_BACKEND_URL}${msg.attachment.url}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="flex items-center gap-2 text-sm underline"
                                    >
                                      <FileText className="w-4 h-4" />
                                      {msg.attachment.filename}
                                    </a>
                                  )}
                                </div>
                              )}
                              <p className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                                {msg.content}
                              </p>
                              
                              {/* Message actions */}
                              <div className="absolute -right-8 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="w-7 h-7 rounded-full">
                                      <MoreVertical className="w-4 h-4" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end" className="w-40">
                                    <DropdownMenuItem onClick={() => setReplyTo(msg)}>
                                      <Reply className="w-4 h-4 mr-2" />
                                      Reply
                                    </DropdownMenuItem>
                                    {isMine && (
                                      <DropdownMenuItem 
                                        onClick={() => handleDeleteMessage(msg.id, true)}
                                        className="text-destructive"
                                      >
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        Delete
                                      </DropdownMenuItem>
                                    )}
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              </div>
                            </div>
                            
                            {/* Delivery status */}
                            {isMine && (
                              <div className="flex items-center mb-1">
                                {msg.pending ? (
                                  <div className="w-3 h-3 border border-muted-foreground border-t-transparent rounded-full animate-spin" />
                                ) : msg.read_by?.length > 0 ? (
                                  <CheckCheck className="w-4 h-4 text-[#007AFF]" />
                                ) : (
                                  <Check className="w-4 h-4 text-muted-foreground" />
                                )}
                              </div>
                            )}
                          </div>
                          
                          <p className={`text-xs text-muted-foreground mt-1 ${isMine ? 'text-right mr-1' : 'ml-1'}`}>
                            {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </p>
                        </div>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>

            {/* Reply preview */}
            {replyTo && (
              <div className="px-6 py-2 border-t border-border bg-secondary/30 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Reply className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">
                    Replying to <span className="font-medium">{replyTo.sender_name}</span>
                  </span>
                </div>
                <Button variant="ghost" size="icon" className="w-6 h-6" onClick={() => setReplyTo(null)}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
            )}

            {/* Message input */}
            <div className="p-4 border-t border-border glass">
              <form onSubmit={handleSendMessage} className="flex items-center gap-3 max-w-3xl mx-auto">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  className="hidden"
                  accept="image/*,.pdf,.doc,.docx"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="rounded-full shrink-0"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Paperclip className="w-5 h-5" />
                </Button>
                
                <Input
                  data-testid="message-input"
                  type="text"
                  placeholder="Type a message..."
                  value={newMessage}
                  onChange={(e) => {
                    setNewMessage(e.target.value);
                    handleTyping();
                  }}
                  className="flex-1 h-12 bg-secondary/50 border-transparent rounded-full px-5"
                />
                
                <Button
                  data-testid="send-message-btn"
                  type="submit"
                  disabled={!newMessage.trim() || sending}
                  className="w-12 h-12 rounded-full shrink-0"
                >
                  <Send className="w-5 h-5" />
                </Button>
              </form>
            </div>
          </>
        ) : (
          // Empty state
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div className="w-20 h-20 bg-secondary rounded-full flex items-center justify-center mx-auto mb-6">
                <MessageCircle className="w-10 h-10 text-muted-foreground" />
              </div>
              <h3 className="text-xl font-bold mb-2" style={{ fontFamily: 'Manrope, sans-serif' }}>
                Select a chat
              </h3>
              <p className="text-muted-foreground">
                Choose a conversation to start messaging
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ChatApp;
