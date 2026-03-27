/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';
import { 
  signInWithPopup, 
  GoogleAuthProvider, 
  onAuthStateChanged, 
  signOut, 
  User as FirebaseUser 
} from 'firebase/auth';
import { 
  collection, 
  query, 
  where, 
  onSnapshot, 
  addDoc, 
  updateDoc, 
  deleteDoc, 
  doc, 
  serverTimestamp, 
  Timestamp,
  getDoc,
  setDoc,
  getDocs,
  deleteField
} from 'firebase/firestore';
import { auth, db } from './firebase';
import CryptoJS from 'crypto-js';
import * as OTPAuth from 'otpauth';
import { QRCodeCanvas } from 'qrcode.react';
import { 
  Shield, 
  Lock, 
  Share2, 
  LayoutDashboard, 
  Plus, 
  Trash2, 
  LogOut, 
  AlertTriangle, 
  Search,
  User as UserIcon,
  ChevronRight,
  Edit2,
  Database,
  Eye,
  EyeOff,
  File as FileIcon,
  Upload,
  Download,
  FileText,
  X,
  Mail,
  Activity,
  Bell,
  Bug,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  ArrowUpRight,
  ArrowDownRight,
  Check,
  Key,
  TrendingUp,
  Zap,
  Clock,
  ExternalLink,
  Settings,
  MoreHorizontal,
  Terminal
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Cell,
  PieChart,
  Pie,
  LineChart,
  Line,
  Legend
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './lib/utils';

// --- Types ---

interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  role: 'admin' | 'user';
  twoFactorEnabled?: boolean;
  twoFactorSecret?: string;
}

interface DataEntry {
  id: string;
  ownerId: string;
  title: string;
  content: string;
  createdAt: Timestamp;
  sharedWith: string[];
  permissions?: { [userId: string]: 'read' | 'write' };
}

interface BreachLog {
  id: string;
  timestamp: Timestamp;
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  ipAddress?: string;
  location?: string;
  userAgent?: string;
  resource?: string;
  status?: 'blocked' | 'logged' | 'flagged';
}

interface FileEntry {
  id: string;
  ownerId: string;
  fileName: string;
  fileType: string;
  encryptedData: string;
  createdAt: Timestamp;
  sharedWith: string[];
  permissions?: { [userId: string]: 'read' | 'write' };
}

interface Notification {
  id: string;
  userId: string;
  title: string;
  message: string;
  type: 'share' | 'security' | 'update';
  read: boolean;
  createdAt: Timestamp;
}

enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId: string | undefined;
    email: string | null | undefined;
    emailVerified: boolean | undefined;
    isAnonymous: boolean | undefined;
    tenantId: string | null | undefined;
    providerInfo: {
      providerId: string;
      displayName: string | null;
      email: string | null;
      photoUrl: string | null;
    }[];
  }
}

// --- Error Handling ---

function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null) {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo: auth.currentUser?.providerData.map(provider => ({
        providerId: provider.providerId,
        displayName: provider.displayName,
        email: provider.email,
        photoUrl: provider.photoURL
      })) || []
    },
    operationType,
    path
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// --- Components ---

const ErrorBoundary = ({ children }: { children: React.ReactNode }) => {
  const [hasError, setHasError] = useState(false);
  const [errorDetails, setErrorDetails] = useState<string | null>(null);

  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      if (event.error?.message) {
        try {
          const parsed = JSON.parse(event.error.message);
          if (parsed.error) {
            setHasError(true);
            setErrorDetails(parsed.error);
          }
        } catch {
          // Not a JSON error
        }
      }
    };
    window.addEventListener('error', handleError);
    return () => window.removeEventListener('error', handleError);
  }, []);

  if (hasError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-red-50 p-4">
        <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8 text-center border border-red-100">
          <ShieldAlert className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Exception</h2>
          <p className="text-gray-600 mb-6">
            A security or permission error occurred. This may be due to insufficient access rights.
          </p>
          <div className="bg-red-50 p-4 rounded-lg text-left mb-6 overflow-auto max-h-40">
            <code className="text-xs text-red-700">{errorDetails}</code>
          </div>
          <button 
            onClick={() => window.location.reload()}
            className="w-full py-3 bg-red-600 text-white rounded-xl font-semibold hover:bg-red-700 transition-colors"
          >
            Reload Application
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-white p-4 rounded-2xl shadow-2xl border border-slate-100">
        <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">{label}</p>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: payload[0].payload.color || payload[0].color }} />
          <p className="text-lg font-display font-bold text-slate-900">{payload[0].value} <span className="text-sm text-slate-400 font-medium">Events</span></p>
        </div>
      </div>
    );
  }
  return null;
};

export default function App() {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [entries, setEntries] = useState<DataEntry[]>([]);
  const [breachLogs, setBreachLogs] = useState<BreachLog[]>([]);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [activeTab, setActiveTab] = useState<'storage' | 'dashboard' | 'security'>('dashboard');
  const [storageSubTab, setStorageSubTab] = useState<'entries' | 'files'>('entries');
  
  // 2FA states
  const [is2FAVerified, setIs2FAVerified] = useState(false);
  const [show2FAVerification, setShow2FAVerification] = useState(false);
  const [show2FASetup, setShow2FASetup] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [tempSecret, setTempSecret] = useState('');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [twoFactorError, setTwoFactorError] = useState('');
  const [isVerifying2FA, setIsVerifying2FA] = useState(false);
  const [pending2FASetup, setPending2FASetup] = useState(false);
  
  // Form states
  const [newTitle, setNewTitle] = useState('');
  const [newContent, setNewContent] = useState('');
  const [showNewForm, setShowNewForm] = useState(false);
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  
  const [shareEmail, setShareEmail] = useState('');
  const [sharingEntryId, setSharingEntryId] = useState<string | null>(null);
  const [sharingFileId, setSharingFileId] = useState<string | null>(null);
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [viewingContentId, setViewingContentId] = useState<string | null>(null);
  const [investigatingLogId, setInvestigatingLogId] = useState<string | null>(null);
  const [shareAccessLevel, setShareAccessLevel] = useState<'read' | 'write'>('read');
  const [collaboratorEmails, setCollaboratorEmails] = useState<{ [uid: string]: string }>({});

  // Encryption Key (In a real app, this would be more complex/secure)
  const getEncryptionKey = () => `secure-vault-key-${user?.uid}`;

  useEffect(() => {
    const fetchCollaboratorEmails = async () => {
      const resourceId = sharingEntryId || sharingFileId;
      if (!resourceId) {
        setCollaboratorEmails({});
        return;
      }

      const resource = sharingEntryId 
        ? entries.find(e => e.id === sharingEntryId)
        : files.find(f => f.id === sharingFileId);

      if (resource && resource.sharedWith && resource.sharedWith.length > 0) {
        const newEmails: { [uid: string]: string } = {};
        for (const uid of resource.sharedWith) {
          if (!collaboratorEmails[uid]) {
            try {
              const userDoc = await getDoc(doc(db, 'users', uid));
              if (userDoc.exists()) {
                newEmails[uid] = userDoc.data().email;
              }
            } catch (error) {
              console.error("Error fetching user email:", error);
            }
          }
        }
        if (Object.keys(newEmails).length > 0) {
          setCollaboratorEmails(prev => ({ ...prev, ...newEmails }));
        }
      }
    };

    fetchCollaboratorEmails();
  }, [sharingEntryId, sharingFileId, entries, files]);

  // --- Auth Logic ---

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);
      if (firebaseUser) {
        // Fetch or create profile
        const userDocRef = doc(db, 'users', firebaseUser.uid);
        try {
          const userDoc = await getDoc(userDocRef);
          if (userDoc.exists()) {
            const data = userDoc.data() as UserProfile;
            setProfile(data);
            
            // Handle 2FA
            if (data.twoFactorEnabled) {
              setShow2FAVerification(true);
              setIs2FAVerified(false);
            } else {
              setIs2FAVerified(true);
              if (pending2FASetup) {
                setup2FA(firebaseUser);
                setPending2FASetup(false);
              }
            }
          } else {
            const newProfile: UserProfile = {
              uid: firebaseUser.uid,
              email: firebaseUser.email || '',
              displayName: firebaseUser.displayName || 'User',
              role: 'user', // Default role
              twoFactorEnabled: false
            };
            await setDoc(userDocRef, newProfile);
            setProfile(newProfile);
            setIs2FAVerified(true);
            if (pending2FASetup) {
              setup2FA(firebaseUser);
              setPending2FASetup(false);
            }
          }
        } catch (error) {
          console.error("Error fetching profile:", error);
        }
      } else {
        setProfile(null);
        setIs2FAVerified(false);
        setShow2FAVerification(false);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const handleLogin = async (trigger2FA = false) => {
    if (trigger2FA) setPending2FASetup(true);
    const provider = new GoogleAuthProvider();
    try {
      await signInWithPopup(auth, provider);
    } catch (error) {
      console.error("Login failed:", error);
      setPending2FASetup(false);
    }
  };

  const handleLogout = () => {
    signOut(auth);
    setIs2FAVerified(false);
    setShow2FAVerification(false);
  };

  // --- 2FA Logic ---

  const setup2FA = (targetUser?: any) => {
    const currentUser = targetUser || user;
    if (!currentUser) return;
    // Generate a random secret
    const secret = new OTPAuth.Secret({ size: 20 });
    const secretBase32 = secret.base32;
    
    // Create a new TOTP object
    const totp = new OTPAuth.TOTP({
      issuer: 'SecureVault',
      label: currentUser.email || 'user',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secret
    });

    setTempSecret(secretBase32);
    setQrCodeUrl(totp.toString());
    setShow2FASetup(true);
  };

  const verifyAndEnable2FA = async () => {
    if (!user || !tempSecret || !twoFactorCode) return;
    setIsVerifying2FA(true);
    setTwoFactorError('');
    
    try {
      const totp = new OTPAuth.TOTP({
        issuer: 'SecureVault',
        label: user.email || 'user',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(tempSecret)
      });

      const delta = totp.validate({
        token: twoFactorCode,
        window: 1
      });

      if (delta !== null) {
        await updateDoc(doc(db, 'users', user.uid), {
          twoFactorEnabled: true,
          twoFactorSecret: tempSecret
        });
        setProfile(prev => prev ? { ...prev, twoFactorEnabled: true, twoFactorSecret: tempSecret } : null);
        setShow2FASetup(false);
        setTwoFactorCode('');
        setIs2FAVerified(true);
        createNotification(user.uid, '2FA Enabled', 'Two-factor authentication has been successfully enabled for your account.', 'security');
      } else {
        setTwoFactorError('Invalid verification code. Please try again.');
      }
    } catch (error) {
      console.error("Error enabling 2FA:", error);
      setTwoFactorError('An error occurred. Please try again.');
    } finally {
      setIsVerifying2FA(false);
    }
  };

  const verifyLogin2FA = () => {
    if (!profile?.twoFactorSecret || !twoFactorCode) return;
    setIsVerifying2FA(true);
    setTwoFactorError('');

    try {
      const totp = new OTPAuth.TOTP({
        issuer: 'SecureVault',
        label: user?.email || 'user',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(profile.twoFactorSecret)
      });

      const delta = totp.validate({
        token: twoFactorCode,
        window: 1
      });

      if (delta !== null) {
        setIs2FAVerified(true);
        setShow2FAVerification(false);
        setTwoFactorCode('');
      } else {
        setTwoFactorError('Invalid verification code. Please try again.');
      }
    } catch (error) {
      console.error("Error verifying 2FA:", error);
      setTwoFactorError('An error occurred. Please try again.');
    } finally {
      setIsVerifying2FA(false);
    }
  };

  const disable2FA = async () => {
    if (!user) return;
    try {
      await updateDoc(doc(db, 'users', user.uid), {
        twoFactorEnabled: false,
        twoFactorSecret: deleteField()
      });
      setProfile(prev => prev ? { ...prev, twoFactorEnabled: false, twoFactorSecret: undefined } : null);
      createNotification(user.uid, '2FA Disabled', 'Two-factor authentication has been disabled for your account.', 'security');
    } catch (error) {
      console.error("Error disabling 2FA:", error);
    }
  };

  // --- Data Logic ---

  useEffect(() => {
    if (!user) return;

    // Listen to entries owned by user or shared with user
    const entriesQuery = query(
      collection(db, 'data_entries'),
      where('ownerId', '==', user.uid)
    );

    const sharedQuery = query(
      collection(db, 'data_entries'),
      where('sharedWith', 'array-contains', user.uid)
    );

    const unsubEntries = onSnapshot(entriesQuery, (snapshot) => {
      const owned = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as DataEntry));
      setEntries(prev => {
        const others = prev.filter(e => e.ownerId !== user.uid);
        return [...owned, ...others].sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
      });
    }, (error) => handleFirestoreError(error, OperationType.GET, 'data_entries'));

    const unsubShared = onSnapshot(sharedQuery, (snapshot) => {
      const shared = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as DataEntry));
      setEntries(prev => {
        const owned = prev.filter(e => e.ownerId === user.uid);
        return [...owned, ...shared].sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
      });
    }, (error) => handleFirestoreError(error, OperationType.GET, 'data_entries'));

    // Listen to files (owned or shared)
    const filesQuery = query(
      collection(db, 'files'),
      where('ownerId', '==', user.uid)
    );

    const sharedFilesQuery = query(
      collection(db, 'files'),
      where('sharedWith', 'array-contains', user.uid)
    );

    const unsubFiles = onSnapshot(filesQuery, (snapshot) => {
      const owned = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as FileEntry));
      setFiles(prev => {
        const others = prev.filter(f => f.ownerId !== user.uid);
        return [...owned, ...others].sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
      });
    }, (error) => handleFirestoreError(error, OperationType.GET, 'files'));

    const unsubSharedFiles = onSnapshot(sharedFilesQuery, (snapshot) => {
      const shared = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as FileEntry));
      setFiles(prev => {
        const owned = prev.filter(f => f.ownerId === user.uid);
        return [...owned, ...shared].sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
      });
    }, (error) => handleFirestoreError(error, OperationType.GET, 'files'));

    // Listen to breach logs (all users can see dashboard stats)
    const unsubLogs = onSnapshot(collection(db, 'breach_logs'), (snapshot) => {
      const logs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as BreachLog));
      setBreachLogs(logs);

      // Check for new high severity logs to notify
      snapshot.docChanges().forEach((change) => {
        if (change.type === 'added') {
          const log = change.doc.data() as BreachLog;
          if (log.severity === 'high') {
            createNotification(user.uid, 'Security Alert', `High severity event detected: ${log.type}`, 'security');
          }
        }
      });
    }, (error) => handleFirestoreError(error, OperationType.GET, 'breach_logs'));

    // Listen to notifications
    const notificationsQuery = query(
      collection(db, 'notifications'),
      where('userId', '==', user.uid)
    );

    const unsubNotifications = onSnapshot(notificationsQuery, (snapshot) => {
      const data = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Notification));
      setNotifications(data.sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0)));
    }, (error) => handleFirestoreError(error, OperationType.GET, 'notifications'));

    return () => {
      unsubEntries();
      unsubShared();
      unsubFiles();
      unsubSharedFiles();
      unsubLogs();
      unsubNotifications();
    };
  }, [user]);

  const addEntry = async () => {
    if (!user || !newTitle || !newContent) return;
    try {
      await addDoc(collection(db, 'data_entries'), {
        ownerId: user.uid,
        title: newTitle,
        content: newContent,
        createdAt: serverTimestamp(),
        sharedWith: []
      });
      setNewTitle('');
      setNewContent('');
      setShowNewForm(false);
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, 'data_entries');
    }
  };

  const updateEntry = async () => {
    if (!user || !editingEntryId || !newTitle || !newContent) return;
    try {
      const entryRef = doc(db, 'data_entries', editingEntryId);
      await updateDoc(entryRef, {
        title: newTitle,
        content: newContent,
        updatedAt: serverTimestamp()
      });
      setNewTitle('');
      setNewContent('');
      setEditingEntryId(null);
      setShowNewForm(false);
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `data_entries/${editingEntryId}`);
    }
  };

  const deleteEntry = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'data_entries', id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `data_entries/${id}`);
    }
  };

  const shareEntry = async () => {
    if (!sharingEntryId || !shareEmail) return;
    try {
      const usersQuery = query(collection(db, 'users'), where('email', '==', shareEmail));
      const userSnapshot = await getDocs(usersQuery);
      
      if (userSnapshot.empty) {
        alert("User not found");
        return;
      }

      const targetUserId = userSnapshot.docs[0].id;
      const entryRef = doc(db, 'data_entries', sharingEntryId);
      const entryDoc = await getDoc(entryRef);
      
      if (entryDoc.exists()) {
        const data = entryDoc.data() as DataEntry;
        const currentShared = data.sharedWith || [];
        const currentPermissions = data.permissions || {};
        
        if (!currentShared.includes(targetUserId) || currentPermissions[targetUserId] !== shareAccessLevel) {
          await updateDoc(entryRef, {
            sharedWith: currentShared.includes(targetUserId) ? currentShared : [...currentShared, targetUserId],
            [`permissions.${targetUserId}`]: shareAccessLevel
          });

          // Notify the target user
          await createNotification(
            targetUserId, 
            'New Data Shared', 
            `${user?.displayName || user?.email} shared a secure entry with you: ${data.title} (${shareAccessLevel} access)`, 
            'share'
          );
        }
      }
      setShareEmail('');
      setSharingEntryId(null);
      setShareAccessLevel('read');
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `data_entries/${sharingEntryId}`);
    }
  };

  // --- File Logic ---

  const handleFileUpload = async () => {
    if (!user || !selectedFile) return;
    setIsUploading(true);

    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const base64Data = e.target?.result as string;
        
        // Encrypt data
        const encrypted = CryptoJS.AES.encrypt(base64Data, getEncryptionKey()).toString();

        // Save to Firestore
        await addDoc(collection(db, 'files'), {
          ownerId: user.uid,
          fileName: selectedFile.name,
          fileType: selectedFile.type,
          encryptedData: encrypted,
          createdAt: serverTimestamp(),
          sharedWith: []
        });

        setSelectedFile(null);
        setShowUploadForm(false);
        setIsUploading(false);
      };
      reader.readAsDataURL(selectedFile);
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, 'files');
      setIsUploading(false);
    }
  };

  const downloadFile = (file: FileEntry) => {
    try {
      // Decrypt data
      const bytes = CryptoJS.AES.decrypt(file.encryptedData, getEncryptionKey());
      const decryptedData = bytes.toString(CryptoJS.enc.Utf8);

      if (!decryptedData) throw new Error("Decryption failed");

      // Create download link
      const link = document.createElement('a');
      link.href = decryptedData;
      link.download = file.fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (error) {
      alert("Failed to decrypt or download file. Ensure you have the correct access.");
      console.error(error);
    }
  };

  const deleteFile = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'files', id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `files/${id}`);
    }
  };

  const shareFile = async () => {
    if (!sharingFileId || !shareEmail) return;
    try {
      const usersQuery = query(collection(db, 'users'), where('email', '==', shareEmail));
      const userSnapshot = await getDocs(usersQuery);
      
      if (userSnapshot.empty) {
        alert("User not found");
        return;
      }

      const targetUserId = userSnapshot.docs[0].id;
      const fileRef = doc(db, 'files', sharingFileId);
      const fileDoc = await getDoc(fileRef);
      
      if (fileDoc.exists()) {
        const data = fileDoc.data() as FileEntry;
        const currentShared = data.sharedWith || [];
        const currentPermissions = data.permissions || {};
        
        if (!currentShared.includes(targetUserId) || currentPermissions[targetUserId] !== shareAccessLevel) {
          await updateDoc(fileRef, {
            sharedWith: currentShared.includes(targetUserId) ? currentShared : [...currentShared, targetUserId],
            [`permissions.${targetUserId}`]: shareAccessLevel
          });

          // Notify the target user
          await createNotification(
            targetUserId, 
            'New File Shared', 
            `${user?.displayName || user?.email} shared a secure file with you: ${data.fileName} (${shareAccessLevel} access)`, 
            'share'
          );
        }
      }
      setShareEmail('');
      setSharingFileId(null);
      setShareAccessLevel('read');
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `files/${sharingFileId}`);
    }
  };

  const removeAccess = async (targetUserId: string) => {
    const resourceId = sharingEntryId || sharingFileId;
    const collectionName = sharingEntryId ? 'data_entries' : 'files';
    if (!resourceId) return;

    try {
      const docRef = doc(db, collectionName, resourceId);
      const docSnap = await getDoc(docRef);
      if (docSnap.exists()) {
        const data = docSnap.data();
        const currentShared = data.sharedWith || [];
        const currentPermissions = data.permissions || {};
        
        const newShared = currentShared.filter((id: string) => id !== targetUserId);
        const newPermissions = { ...currentPermissions };
        delete newPermissions[targetUserId];

        await updateDoc(docRef, {
          sharedWith: newShared,
          permissions: newPermissions
        });
      }
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `${collectionName}/${resourceId}`);
    }
  };

  const updateAccessLevel = async (targetUserId: string, newLevel: 'read' | 'write') => {
    const resourceId = sharingEntryId || sharingFileId;
    const collectionName = sharingEntryId ? 'data_entries' : 'files';
    if (!resourceId) return;

    try {
      const docRef = doc(db, collectionName, resourceId);
      await updateDoc(docRef, {
        [`permissions.${targetUserId}`]: newLevel
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `${collectionName}/${resourceId}`);
    }
  };

  // --- Dashboard Data ---

  const createNotification = async (userId: string, title: string, message: string, type: 'share' | 'security' | 'update') => {
    try {
      await addDoc(collection(db, 'notifications'), {
        userId,
        title,
        message,
        type,
        read: false,
        createdAt: serverTimestamp()
      });
    } catch (error) {
      console.error('Failed to create notification:', error);
    }
  };

  const markNotificationAsRead = async (id: string) => {
    try {
      await updateDoc(doc(db, 'notifications', id), { read: true });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `notifications/${id}`);
    }
  };

  const deleteNotification = async (id: string) => {
    try {
      await deleteDoc(doc(db, 'notifications', id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `notifications/${id}`);
    }
  };

  const simulateSecurityAlert = async () => {
    try {
      const alertTypes = [
        { type: "Unauthorized Access Attempt", severity: 'high' as const, status: 'blocked' as const },
        { type: "Brute Force Detected", severity: 'high' as const, status: 'blocked' as const },
        { type: "Suspicious API Call", severity: 'medium' as const, status: 'flagged' as const },
        { type: "Resource Access Denied", severity: 'low' as const, status: 'logged' as const }
      ];
      
      const selectedAlert = alertTypes[Math.floor(Math.random() * alertTypes.length)];
      const location = ['London, UK', 'Tokyo, JP', 'New York, US', 'Berlin, DE', 'Moscow, RU', 'Beijing, CN'][Math.floor(Math.random() * 6)];
      const ipAddress = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      const resource = ['/api/auth/login', '/api/vault/decrypt', '/api/admin/config', '/api/files/download'][Math.floor(Math.random() * 4)];
      const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

      await addDoc(collection(db, 'breach_logs'), {
        timestamp: serverTimestamp(),
        type: selectedAlert.type,
        description: `A ${selectedAlert.type.toLowerCase()} was detected from ${location} (${ipAddress}).`,
        severity: selectedAlert.severity,
        status: selectedAlert.status,
        ipAddress,
        location,
        userAgent,
        resource
      });
      
      // The onSnapshot listener for breach_logs will automatically trigger the notification
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, 'breach_logs');
    }
  };

  const seedSampleData = async () => {
    if (!user) return;
    try {
      // Add a sample entry
      await addDoc(collection(db, 'data_entries'), {
        ownerId: user.uid,
        title: 'Project Phoenix Credentials',
        content: 'AES-256: [ENCRYPTED_PAYLOAD_SAMPLE]',
        createdAt: serverTimestamp(),
        sharedWith: []
      });

      // Add a sample file
      await addDoc(collection(db, 'files'), {
        ownerId: user.uid,
        fileName: 'Q1_Security_Audit.pdf',
        fileType: 'application/pdf',
        encryptedData: 'AES-256: [ENCRYPTED_FILE_SAMPLE]',
        createdAt: serverTimestamp(),
        sharedWith: []
      });

      createNotification(user.uid, 'System Seeded', 'Sample data has been successfully added to your vault.', 'update');
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, 'data_entries');
    }
  };

  const sendTestNotification = async () => {
    if (!user) return;
    await createNotification(
      user.uid, 
      'Test Notification', 
      'This is a test notification to verify the real-time alerting system is working correctly.', 
      'update'
    );
  };

  const chartData = useMemo(() => {
    const counts: Record<string, number> = { low: 0, medium: 0, high: 0 };
    breachLogs.forEach(log => {
      counts[log.severity]++;
    });
    return [
      { name: 'Low', value: counts.low, color: '#10b981' },
      { name: 'Medium', value: counts.medium, color: '#f59e0b' },
      { name: 'High', value: counts.high, color: '#ef4444' },
    ];
  }, [breachLogs]);

  const timelineData = useMemo(() => {
    const daily: Record<string, number> = {};
    breachLogs.forEach(log => {
      if (log.timestamp) {
        const date = log.timestamp.toDate().toLocaleDateString();
        daily[date] = (daily[date] || 0) + 1;
      }
    });
    return Object.entries(daily).map(([date, count]) => ({ date, count })).sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  }, [breachLogs]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <motion.div 
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
        >
          <Shield className="w-12 h-12 text-indigo-600" />
        </motion.div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-[#020617] flex flex-col items-center justify-center p-6 relative overflow-hidden font-sans">
        <div className="dynamic-bg" />
        
        {/* Animated Background Accents */}
        <div className="absolute top-0 left-0 w-full h-full pointer-events-none">
          <motion.div 
            animate={{ 
              scale: [1, 1.2, 1],
              x: [0, 50, 0],
              y: [0, 30, 0]
            }}
            transition={{ duration: 20, repeat: Infinity, ease: "easeInOut" }}
            className="bg-blob w-[800px] h-[800px] bg-brand-600/30 -top-1/4 -left-1/4" 
          />
          <motion.div 
            animate={{ 
              scale: [1.2, 1, 1.2],
              x: [0, -40, 0],
              y: [0, -20, 0]
            }}
            transition={{ duration: 25, repeat: Infinity, ease: "easeInOut" }}
            className="bg-blob w-[600px] h-[600px] bg-indigo-600/20 -bottom-1/4 -right-1/4" 
          />
        </div>

        <motion.div 
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="max-w-xl w-full text-center z-10"
        >
          <div className="inline-flex p-6 rounded-[2.5rem] bg-brand-500/10 border border-brand-500/20 mb-12 shadow-[0_0_50px_-12px_rgba(51,85,255,0.4)] animate-float-slow">
            <Shield className="w-20 h-20 text-brand-400" />
          </div>
          <h1 className="text-6xl md:text-8xl font-display font-bold text-white mb-8 tracking-tight leading-[0.9]">
            SecureVault <span className="gradient-text italic">Business</span>
          </h1>
          <p className="text-slate-400 mb-14 text-xl leading-relaxed font-light max-w-lg mx-auto">
            The next-generation platform for <span className="text-white font-medium">end-to-end encrypted</span> data storage and real-time threat intelligence.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-6 justify-center">
            <button 
              onClick={() => handleLogin(true)}
              className="px-10 py-6 bg-brand-600 hover:bg-brand-500 text-white rounded-3xl font-bold text-xl transition-all flex items-center justify-center gap-3 shadow-2xl shadow-brand-500/30 group active:scale-95"
            >
              <Lock className="w-6 h-6 group-hover:scale-110 transition-transform" />
              Get Started with College
            </button>
            <button className="px-10 py-6 bg-white/5 hover:bg-white/10 text-white border border-white/10 rounded-3xl font-bold text-xl transition-all backdrop-blur-xl">
              Security Specs
            </button>
          </div>
          
          <div className="mt-24 flex items-center justify-center gap-12 opacity-30 grayscale hover:grayscale-0 transition-all duration-700">
            <div className="flex flex-col items-center gap-3">
              <Shield className="w-6 h-6" />
              <span className="text-[10px] font-black uppercase tracking-[0.2em]">AES-256</span>
            </div>
            <div className="flex flex-col items-center gap-3">
              <Lock className="w-6 h-6" />
              <span className="text-[10px] font-black uppercase tracking-[0.2em]">Zero Knowledge</span>
            </div>
            <div className="flex flex-col items-center gap-3">
              <AlertTriangle className="w-6 h-6" />
              <span className="text-[10px] font-black uppercase tracking-[0.2em]">Real-time</span>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen flex flex-col font-sans relative">
        <div className="dynamic-bg" />
        
        {/* Animated Background Accents */}
        <div className="fixed inset-0 pointer-events-none overflow-hidden">
          <motion.div 
            animate={{ 
              scale: [1, 1.1, 1],
              x: [0, 30, 0],
              y: [0, 20, 0]
            }}
            transition={{ duration: 30, repeat: Infinity, ease: "easeInOut" }}
            className="bg-blob w-[1000px] h-[1000px] bg-brand-600/10 -top-1/2 -left-1/4" 
          />
          <motion.div 
            animate={{ 
              scale: [1.1, 1, 1.1],
              x: [0, -20, 0],
              y: [0, -30, 0]
            }}
            transition={{ duration: 35, repeat: Infinity, ease: "easeInOut" }}
            className="bg-blob w-[800px] h-[800px] bg-indigo-600/10 -bottom-1/2 -right-1/4" 
          />
        </div>

        {/* Header */}
        <header className="bg-slate-900/40 backdrop-blur-2xl border-b border-slate-800/50 sticky top-0 z-30">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-24 flex items-center justify-between">
            <div className="flex items-center gap-5">
              <div className="p-3 bg-brand-600 rounded-2xl shadow-2xl shadow-brand-500/30 animate-float-slow">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <span className="text-3xl font-display font-bold text-white hidden sm:block tracking-tight">SecureVault</span>
            </div>

            <nav className="flex items-center bg-slate-950/50 p-2 rounded-[1.5rem] border border-slate-800/50 backdrop-blur-xl">
              <button 
                onClick={() => setActiveTab('dashboard')}
                className={cn(
                  "px-8 py-3 rounded-2xl text-sm font-bold transition-all flex items-center gap-2",
                  activeTab === 'dashboard' ? "bg-brand-600 text-white shadow-xl shadow-brand-500/20" : "text-slate-400 hover:text-white"
                )}
              >
                <LayoutDashboard className="w-4 h-4" />
                Dashboard
              </button>
              <button 
                onClick={() => setActiveTab('storage')}
                className={cn(
                  "px-8 py-3 rounded-2xl text-sm font-bold transition-all flex items-center gap-2",
                  activeTab === 'storage' ? "bg-brand-600 text-white shadow-xl shadow-brand-500/20" : "text-slate-400 hover:text-white"
                )}
              >
                <Database className="w-4 h-4" />
                Storage
              </button>
              <button 
                onClick={() => setActiveTab('security')}
                className={cn(
                  "px-8 py-3 rounded-2xl text-sm font-bold transition-all flex items-center gap-2",
                  activeTab === 'security' ? "bg-brand-600 text-white shadow-xl shadow-brand-500/20" : "text-slate-400 hover:text-white"
                )}
              >
                <ShieldCheck className="w-4 h-4" />
                Security
              </button>
            </nav>

            <div className="flex items-center gap-6">
              {/* Notifications */}
              <div className="relative">
                <button 
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="p-3.5 text-slate-400 hover:text-white hover:bg-white/5 rounded-2xl transition-all relative group"
                >
                  <Bell className="w-7 h-7 group-hover:scale-110 transition-transform" />
                  {notifications.filter(n => !n.read).length > 0 && (
                    <span className="absolute top-3 right-3 w-3.5 h-3.5 bg-red-500 border-2 border-slate-900 rounded-full animate-pulse" />
                  )}
                </button>

                <AnimatePresence>
                  {showNotifications && (
                    <motion.div
                      initial={{ opacity: 0, y: 10, scale: 0.95 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: 10, scale: 0.95 }}
                      className="absolute right-0 mt-6 w-[400px] bg-slate-900/95 backdrop-blur-3xl rounded-[2.5rem] shadow-[0_30px_100px_-20px_rgba(0,0,0,0.5)] border border-slate-800/50 overflow-hidden z-50"
                    >
                      <div className="p-8 border-b border-slate-800/50 flex items-center justify-between bg-slate-950/30">
                        <h3 className="font-display font-bold text-white text-xl">Notifications</h3>
                        <span className="px-4 py-1.5 bg-brand-500/20 text-brand-400 text-[10px] font-black rounded-full uppercase tracking-widest">
                          {notifications.filter(n => !n.read).length} New
                        </span>
                      </div>
                      <div className="max-h-[500px] overflow-y-auto p-6 space-y-4">
                        {notifications.length === 0 ? (
                          <div className="py-16 text-center">
                            <div className="w-20 h-20 bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-6">
                              <Bell className="w-10 h-10 text-slate-600" />
                            </div>
                            <p className="text-slate-500 font-bold uppercase tracking-widest text-xs">No notifications yet</p>
                          </div>
                        ) : (
                          notifications.map(notification => (
                            <motion.div
                              key={notification.id}
                              layout
                              className={cn(
                                "p-5 rounded-3xl border transition-all relative group",
                                notification.read ? "bg-slate-900/50 border-slate-800/30" : "bg-brand-500/5 border-brand-500/20 shadow-lg"
                              )}
                            >
                              <div className="flex gap-5">
                                <div className={cn(
                                  "w-14 h-14 rounded-2xl flex items-center justify-center shrink-0",
                                  notification.type === 'share' ? "bg-blue-500/10 text-blue-400" :
                                  notification.type === 'security' ? "bg-red-500/10 text-red-400" :
                                  "bg-amber-500/10 text-amber-400"
                                )}>
                                  {notification.type === 'share' ? <Share2 className="w-7 h-7" /> :
                                   notification.type === 'security' ? <ShieldAlert className="w-7 h-7" /> :
                                   <RefreshCw className="w-7 h-7" />}
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-start justify-between gap-2 mb-2">
                                    <h4 className="font-bold text-white text-sm truncate">{notification.title}</h4>
                                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest whitespace-nowrap">
                                      {notification.createdAt?.toDate()?.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) || 'Just now'}
                                    </span>
                                  </div>
                                  <p className="text-sm text-slate-400 leading-relaxed line-clamp-2 mb-4">
                                    {notification.message}
                                  </p>
                                  <div className="flex items-center gap-4">
                                    {!notification.read && (
                                      <button 
                                        onClick={() => markNotificationAsRead(notification.id)}
                                        className="text-[10px] font-black text-brand-400 hover:text-brand-300 uppercase tracking-widest"
                                      >
                                        Mark as read
                                      </button>
                                    )}
                                    <button 
                                      onClick={() => deleteNotification(notification.id)}
                                      className="text-[10px] font-black text-slate-600 hover:text-red-400 uppercase tracking-widest"
                                    >
                                      Delete
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </motion.div>
                          ))
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              <div className="h-10 w-[1px] bg-slate-800/50 mx-4 hidden md:block" />

              <div className="flex items-center gap-4">
                <div className="text-right hidden md:block">
                  <p className="text-sm font-bold text-white leading-none mb-1">{profile?.displayName}</p>
                  <p className="text-[10px] font-black text-brand-400 uppercase tracking-widest">{profile?.role || 'User'}</p>
                </div>
                <button 
                  onClick={handleLogout}
                  className="w-14 h-14 bg-slate-800/50 hover:bg-red-500/10 rounded-2xl flex items-center justify-center transition-all group border border-slate-800/50"
                  title="Logout"
                >
                  <LogOut className="w-6 h-6 text-slate-500 group-hover:text-red-400 transition-colors" />
                </button>
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-10">
          <AnimatePresence mode="wait">
            {show2FAVerification ? (
              <motion.div
                key="2fa-verify"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="max-w-md mx-auto mt-20"
              >
                <div className="bg-white rounded-[2.5rem] shadow-2xl p-10 border border-slate-100 text-center">
                  <div className="w-20 h-20 bg-brand-50 rounded-[2rem] flex items-center justify-center mx-auto mb-8">
                    <ShieldCheck className="w-10 h-10 text-brand-600" />
                  </div>
                  <h2 className="text-3xl font-display font-bold text-slate-900 mb-4 tracking-tight">Two-Factor Auth</h2>
                  <p className="text-slate-500 mb-10 leading-relaxed">
                    Enter the 6-digit verification code from your authenticator app to access your secure vault.
                  </p>
                  
                  <div className="space-y-6">
                    <div>
                      <input 
                        type="text"
                        maxLength={6}
                        value={twoFactorCode}
                        onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, ''))}
                        placeholder="000000"
                        className="w-full text-center text-4xl font-mono tracking-[0.5em] py-6 rounded-2xl border border-slate-200 focus:ring-4 focus:ring-brand-500/10 focus:border-brand-500 outline-none transition-all text-slate-900"
                      />
                      {twoFactorError && <p className="text-red-500 text-sm mt-3 font-bold">{twoFactorError}</p>}
                    </div>
                    
                    <button 
                      onClick={verifyLogin2FA}
                      disabled={twoFactorCode.length !== 6 || isVerifying2FA}
                      className={cn(
                        "w-full py-5 rounded-2xl font-bold text-lg transition-all shadow-xl flex items-center justify-center gap-3",
                        twoFactorCode.length === 6 && !isVerifying2FA ? "bg-brand-600 text-white hover:bg-brand-500 shadow-brand-500/20" : "bg-slate-100 text-slate-400 cursor-not-allowed"
                      )}
                    >
                      {isVerifying2FA ? (
                        <div className="w-6 h-6 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      ) : (
                        <>
                          <Lock className="w-5 h-5" />
                          Verify & Unlock
                        </>
                      )}
                    </button>
                    
                    <button 
                      onClick={handleLogout}
                      className="text-sm font-bold text-slate-400 hover:text-slate-600 uppercase tracking-widest"
                    >
                      Cancel & Logout
                    </button>
                  </div>
                </div>
              </motion.div>
            ) : activeTab === 'storage' ? (
              <motion.div 
                key="storage"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-10"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-8">
                  <div>
                    <h2 className="text-5xl font-display font-bold text-white tracking-tight">Secure Storage</h2>
                    <p className="text-slate-400 text-lg mt-4 font-medium">Manage and share your sensitive business data with zero-knowledge encryption.</p>
                  </div>
                  <div className="flex gap-4">
                    <button 
                      onClick={() => setShowUploadForm(true)}
                      className="inline-flex items-center justify-center gap-3 px-8 py-5 bg-slate-800/50 text-white border border-slate-700/50 rounded-2xl font-black uppercase tracking-widest text-xs hover:bg-slate-700 transition-all backdrop-blur-md active:scale-95"
                    >
                      <Upload className="w-5 h-5" />
                      Upload File
                    </button>
                    <button 
                      onClick={() => setShowNewForm(true)}
                      className="inline-flex items-center justify-center gap-3 px-8 py-5 bg-brand-600 text-white rounded-2xl font-black uppercase tracking-widest text-xs hover:bg-brand-500 transition-all shadow-2xl shadow-brand-500/30 active:scale-95"
                    >
                      <Plus className="w-5 h-5" />
                      New Entry
                    </button>
                  </div>
                </div>

                {/* Sub-tabs */}
                <div className="flex gap-2 p-2 bg-slate-950/50 rounded-2xl w-fit border border-slate-800/50 backdrop-blur-md">
                  <button 
                    onClick={() => setStorageSubTab('entries')}
                    className={cn(
                      "px-10 py-4 text-xs font-black uppercase tracking-widest transition-all rounded-xl",
                      storageSubTab === 'entries' ? "bg-brand-600 text-white shadow-2xl shadow-brand-600/20" : "text-slate-500 hover:text-slate-300"
                    )}
                  >
                    Data Entries
                  </button>
                  <button 
                    onClick={() => setStorageSubTab('files')}
                    className={cn(
                      "px-10 py-4 text-xs font-black uppercase tracking-widest transition-all rounded-xl",
                      storageSubTab === 'files' ? "bg-brand-600 text-white shadow-2xl shadow-brand-600/20" : "text-slate-500 hover:text-slate-300"
                    )}
                  >
                    Encrypted Files
                  </button>
                </div>

                {/* New Entry Form Modal */}
                {showNewForm && (
                  <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-xl z-[100] flex items-center justify-center p-4">
                    <motion.div 
                      initial={{ scale: 0.9, opacity: 0, y: 20 }}
                      animate={{ scale: 1, opacity: 1, y: 0 }}
                      className="bg-slate-900 rounded-[3rem] shadow-2xl w-full max-w-lg overflow-hidden border border-slate-800"
                    >
                      <div className="p-10 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
                        <h3 className="text-3xl font-display font-bold text-white tracking-tight">{editingEntryId ? 'Edit Secure Entry' : 'Create Secure Entry'}</h3>
                        <button onClick={() => { setShowNewForm(false); setEditingEntryId(null); setNewTitle(''); setNewContent(''); }} className="p-3 text-slate-500 hover:text-white hover:bg-slate-800 rounded-2xl transition-all">
                          <X className="w-7 h-7" />
                        </button>
                      </div>
                      <div className="p-10 space-y-8">
                        <div>
                          <label className="block text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3">Entry Title</label>
                          <input 
                            type="text" 
                            value={newTitle}
                            onChange={(e) => setNewTitle(e.target.value)}
                            placeholder="e.g., Q1 Financial Projections"
                            className="w-full px-8 py-5 rounded-2xl bg-slate-950 border border-slate-800 focus:ring-4 focus:ring-brand-500/10 focus:border-brand-500 outline-none transition-all font-medium text-white placeholder:text-slate-700"
                          />
                        </div>
                        <div>
                          <label className="block text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3">Sensitive Content</label>
                          <textarea 
                            value={newContent}
                            onChange={(e) => setNewContent(e.target.value)}
                            placeholder="Paste sensitive data here..."
                            rows={6}
                            className="w-full px-8 py-5 rounded-2xl bg-slate-950 border border-slate-800 focus:ring-4 focus:ring-brand-500/10 focus:border-brand-500 outline-none transition-all resize-none font-mono text-sm text-slate-400 placeholder:text-slate-700"
                          />
                        </div>
                      </div>
                      <div className="p-10 bg-slate-950/50 flex gap-5 border-t border-slate-800">
                        <button 
                          onClick={() => { setShowNewForm(false); setEditingEntryId(null); setNewTitle(''); setNewContent(''); }}
                          className="flex-1 py-5 text-slate-500 font-black uppercase tracking-widest text-xs hover:text-white hover:bg-slate-800 rounded-2xl transition-all border border-transparent active:scale-95"
                        >
                          Cancel
                        </button>
                        <button 
                          onClick={editingEntryId ? updateEntry : addEntry}
                          className="flex-1 py-5 bg-brand-600 text-white font-black uppercase tracking-widest text-xs hover:bg-brand-500 rounded-2xl transition-all shadow-2xl shadow-brand-500/30 active:scale-95"
                        >
                          {editingEntryId ? 'Update Entry' : 'Save Securely'}
                        </button>
                      </div>
                    </motion.div>
                  </div>
                )}

                {/* File Upload Modal */}
                {showUploadForm && (
                  <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-xl z-[100] flex items-center justify-center p-4">
                    <motion.div 
                      initial={{ scale: 0.9, opacity: 0, y: 20 }}
                      animate={{ scale: 1, opacity: 1, y: 0 }}
                      className="bg-slate-900 rounded-[3rem] shadow-2xl w-full max-w-lg overflow-hidden border border-slate-800"
                    >
                      <div className="p-10 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
                        <h3 className="text-3xl font-display font-bold text-white tracking-tight">Encrypt & Upload</h3>
                        <button onClick={() => setShowUploadForm(false)} className="p-3 text-slate-500 hover:text-white hover:bg-slate-800 rounded-2xl transition-all">
                          <X className="w-7 h-7" />
                        </button>
                      </div>
                      <div className="p-10 space-y-10">
                        <div 
                          className={cn(
                            "border-2 border-dashed rounded-[2.5rem] p-16 text-center transition-all group",
                            selectedFile ? "border-brand-500 bg-brand-500/5 shadow-2xl shadow-brand-500/10" : "border-slate-800 hover:border-brand-500/50 hover:bg-slate-800/50"
                          )}
                          onDragOver={(e) => e.preventDefault()}
                          onDrop={(e) => {
                            e.preventDefault();
                            if (e.dataTransfer.files[0]) setSelectedFile(e.dataTransfer.files[0]);
                          }}
                        >
                          {selectedFile ? (
                            <div className="flex flex-col items-center">
                              <div className="p-6 bg-brand-500/10 rounded-3xl text-brand-400 mb-8 shadow-2xl shadow-brand-500/20 border border-brand-500/20">
                                <FileIcon className="w-14 h-14" />
                              </div>
                              <p className="font-bold text-white text-xl mb-2">{selectedFile.name}</p>
                              <p className="text-[10px] text-slate-500 font-black uppercase tracking-[0.2em]">{(selectedFile.size / 1024).toFixed(2)} KB</p>
                              <button 
                                onClick={() => setSelectedFile(null)}
                                className="mt-8 text-xs text-red-400 font-black uppercase tracking-widest hover:text-red-300 transition-colors"
                              >
                                Remove File
                              </button>
                            </div>
                          ) : (
                            <div className="flex flex-col items-center">
                              <div className="p-6 bg-slate-800 rounded-3xl text-slate-600 mb-8 group-hover:scale-110 group-hover:text-brand-400 transition-all border border-slate-700/50">
                                <Upload className="w-14 h-14" />
                              </div>
                              <p className="font-bold text-white text-xl mb-3">Drop your file here</p>
                              <p className="text-sm text-slate-500 mb-10 max-w-[240px] mx-auto font-medium">Files are encrypted locally before upload. Max 1MB.</p>
                              <input 
                                type="file" 
                                id="file-upload"
                                className="hidden"
                                onChange={(e) => e.target.files && setSelectedFile(e.target.files[0])}
                              />
                              <label 
                                htmlFor="file-upload"
                                className="px-10 py-4 bg-white text-slate-900 rounded-2xl text-xs font-black uppercase tracking-widest cursor-pointer hover:bg-slate-100 transition-all shadow-2xl active:scale-95"
                              >
                                Select File
                              </label>
                            </div>
                          )}
                        </div>
                        
                        <div className="bg-brand-500/5 border border-brand-500/10 rounded-[2rem] p-8 flex gap-6">
                          <div className="p-3 bg-slate-900 rounded-2xl shadow-2xl border border-brand-500/20 h-fit">
                            <Shield className="w-6 h-6 text-brand-400 shrink-0" />
                          </div>
                          <p className="text-xs text-slate-400 leading-relaxed font-medium">
                            Zero-knowledge architecture: Your encryption keys never leave your device. 
                            We cannot access your data under any circumstances.
                          </p>
                        </div>
                      </div>
                      <div className="p-10 bg-slate-950/50 flex gap-5 border-t border-slate-800">
                        <button 
                          onClick={() => setShowUploadForm(false)}
                          className="flex-1 py-5 text-slate-500 font-black uppercase tracking-widest text-xs hover:text-white hover:bg-slate-800 rounded-2xl transition-all border border-transparent active:scale-95"
                        >
                          Cancel
                        </button>
                        <button 
                          onClick={handleFileUpload}
                          disabled={!selectedFile || isUploading}
                          className={cn(
                            "flex-1 py-5 text-white font-black uppercase tracking-widest text-xs rounded-2xl transition-all shadow-2xl shadow-brand-500/30 active:scale-95 flex items-center justify-center gap-3",
                            !selectedFile || isUploading ? "bg-slate-800 text-slate-600 cursor-not-allowed border border-slate-700/50" : "bg-brand-600 hover:bg-brand-500 shadow-brand-500/30"
                          )}
                        >
                          {isUploading ? (
                            <>
                              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                              Encrypting...
                            </>
                          ) : (
                            <>
                              <Lock className="w-4 h-4" />
                              Encrypt & Save
                            </>
                          )}
                        </button>
                      </div>
                    </motion.div>
                  </div>
                )}

                {/* Content Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                  {storageSubTab === 'entries' ? (
                    entries.length === 0 ? (
                      <div className="col-span-full py-40 text-center bg-slate-900/50 rounded-[3rem] border-2 border-dashed border-slate-800 backdrop-blur-md">
                        <div className="p-8 bg-slate-800 rounded-full w-fit mx-auto mb-8 text-slate-600">
                          <Database className="w-20 h-20" />
                        </div>
                        <p className="text-white text-2xl font-display font-bold mb-4">No secure entries found</p>
                        <p className="text-slate-500 max-w-md mx-auto font-medium">Create your first zero-knowledge encrypted entry to keep your sensitive business data safe.</p>
                      </div>
                    ) : (
                      entries.map((entry) => (
                        <motion.div 
                          layout
                          key={entry.id}
                          className="bg-slate-900/50 backdrop-blur-xl rounded-[2.5rem] p-10 border border-slate-800/50 hover:border-brand-500/30 transition-all group shadow-2xl shadow-black/20"
                        >
                          <div className="flex items-start justify-between mb-8">
                            <div className="p-5 bg-brand-500/10 rounded-2xl text-brand-400 shadow-2xl shadow-brand-500/10 border border-brand-500/20">
                              <Lock className="w-7 h-7" />
                            </div>
                            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-all transform translate-x-2 group-hover:translate-x-0">
                              {(entry.ownerId === user?.uid || entry.permissions?.[user?.uid || ''] === 'write') && (
                                <button 
                                  onClick={() => {
                                    setEditingEntryId(entry.id);
                                    setNewTitle(entry.title);
                                    setNewContent(entry.content);
                                    setShowNewForm(true);
                                  }}
                                  className="p-3 text-slate-500 hover:text-brand-400 hover:bg-slate-800 rounded-xl transition-all"
                                  title="Edit"
                                >
                                  <Edit2 className="w-5 h-5" />
                                </button>
                              )}
                              {entry.ownerId === user?.uid && (
                                <button 
                                  onClick={() => setSharingEntryId(entry.id)}
                                  className="p-3 text-slate-500 hover:text-brand-400 hover:bg-slate-800 rounded-xl transition-all"
                                  title="Share"
                                >
                                  <Share2 className="w-5 h-5" />
                                </button>
                              )}
                              {entry.ownerId === user?.uid && (
                                <button 
                                  onClick={() => deleteEntry(entry.id)}
                                  className="p-3 text-slate-500 hover:text-red-400 hover:bg-slate-800 rounded-xl transition-all"
                                  title="Delete"
                                >
                                  <Trash2 className="w-5 h-5" />
                                </button>
                              )}
                            </div>
                          </div>
                          <h4 className="text-2xl font-display font-bold text-white mb-2 tracking-tight truncate">{entry.title}</h4>
                          <p className="text-[10px] text-slate-500 mb-8 font-black uppercase tracking-[0.2em]">
                            {entry.createdAt?.toDate()?.toLocaleDateString() || 'Pending...'} • {entry.ownerId === user?.uid ? 'Owned' : `Shared (${entry.permissions?.[user?.uid || ''] || 'read'})`}
                          </p>
                          
                          <div className="relative">
                            <div className={cn(
                              "p-6 bg-slate-950/80 rounded-[2rem] font-mono text-xs text-slate-400 overflow-hidden transition-all border border-slate-800/50",
                              viewingContentId === entry.id ? "max-h-96" : "max-h-24"
                            )}>
                              {viewingContentId === entry.id ? entry.content : '••••••••••••••••••••••••••••••••'}
                            </div>
                            <button 
                              onClick={() => setViewingContentId(viewingContentId === entry.id ? null : entry.id)}
                              className="absolute bottom-4 right-4 p-3 bg-slate-800 shadow-2xl rounded-2xl text-slate-400 hover:text-brand-400 transition-all active:scale-90 border border-slate-700/50"
                            >
                              {viewingContentId === entry.id ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                            </button>
                          </div>

                          {entry.sharedWith.length > 0 && (
                            <div className="mt-6 flex items-center gap-3 pt-6 border-t border-slate-100">
                              <div className="flex -space-x-2">
                                {entry.sharedWith.slice(0, 3).map((uid) => (
                                  <div key={uid} className="w-8 h-8 rounded-full bg-slate-200 border-2 border-white flex items-center justify-center text-[10px] font-bold text-slate-500">
                                    U
                                  </div>
                                ))}
                                {entry.sharedWith.length > 3 && (
                                  <div className="w-8 h-8 rounded-full bg-slate-100 border-2 border-white flex items-center justify-center text-[10px] font-bold text-slate-400">
                                    +{entry.sharedWith.length - 3}
                                  </div>
                                )}
                              </div>
                              <span className="text-[10px] text-slate-400 font-black uppercase tracking-widest">Shared Access</span>
                            </div>
                          )}
                        </motion.div>
                      ))
                    )
                  ) : (
                    files.length === 0 ? (
                      <div className="col-span-full py-32 text-center bg-white rounded-[2.5rem] border-2 border-dashed border-slate-200">
                        <FileIcon className="w-16 h-16 text-slate-300 mx-auto mb-6" />
                        <p className="text-slate-500 text-xl font-medium">No encrypted files found. Upload your first one!</p>
                      </div>
                    ) : (
                      files.map((file) => (
                        <motion.div 
                          layout
                          key={file.id}
                          className="bento-item group"
                        >
                          <div className="flex items-start justify-between mb-6">
                            <div className="p-4 bg-brand-50 rounded-2xl text-brand-600 shadow-sm">
                              <FileText className="w-6 h-6" />
                            </div>
                            <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button 
                                onClick={() => downloadFile(file)}
                                className="p-2.5 text-slate-400 hover:text-brand-600 hover:bg-brand-50 rounded-xl transition-all"
                                title="Download & Decrypt"
                              >
                                <Download className="w-4 h-4" />
                              </button>
                              {file.ownerId === user.uid && (
                                <button 
                                  onClick={() => setSharingFileId(file.id)}
                                  className="p-2.5 text-slate-400 hover:text-brand-600 hover:bg-brand-50 rounded-xl transition-all"
                                  title="Share"
                                >
                                  <Share2 className="w-4 h-4" />
                                </button>
                              )}
                              {file.ownerId === user.uid && (
                                <button 
                                  onClick={() => deleteFile(file.id)}
                                  className="p-2.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-xl transition-all"
                                  title="Delete"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              )}
                            </div>
                          </div>
                          <h4 className="text-xl font-display font-bold text-slate-900 mb-2 truncate">{file.fileName}</h4>
                          <p className="text-xs text-slate-400 mb-6 font-bold uppercase tracking-widest">
                            {file.fileType.split('/')[1] || 'FILE'} • {file.ownerId === user?.uid ? 'Owned' : `Shared (${file.permissions?.[user?.uid || ''] || 'read'})`}
                          </p>
                          
                          <div className="p-5 bg-slate-50 rounded-2xl flex items-center gap-4 border border-slate-100">
                            <div className="w-10 h-10 rounded-xl bg-brand-100 flex items-center justify-center shadow-sm">
                              <Lock className="w-5 h-5 text-brand-600" />
                            </div>
                            <div className="flex-1">
                              <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden">
                                <motion.div 
                                  initial={{ width: 0 }}
                                  animate={{ width: "100%" }}
                                  transition={{ duration: 1.5, ease: "easeOut" }}
                                  className="h-full bg-brand-500" 
                                />
                              </div>
                              <p className="text-[10px] text-slate-500 mt-2 font-black tracking-widest uppercase">AES-256 ENCRYPTED</p>
                            </div>
                          </div>

                          {file.sharedWith.length > 0 && (
                            <div className="mt-6 flex items-center gap-3 pt-6 border-t border-slate-100">
                              <div className="flex -space-x-2">
                                {file.sharedWith.slice(0, 3).map((uid) => (
                                  <div key={uid} className="w-8 h-8 rounded-full bg-slate-200 border-2 border-white flex items-center justify-center text-[10px] font-bold text-slate-500">
                                    U
                                  </div>
                                ))}
                              </div>
                              <span className="text-[10px] text-slate-400 font-black uppercase tracking-widest">Shared Access</span>
                            </div>
                          )}
                        </motion.div>
                      ))
                    )
                  )}
                </div>

                {/* Share Modal */}
                {(sharingEntryId || sharingFileId) && (
                  <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-md z-50 flex items-center justify-center p-4">
                    <motion.div 
                      initial={{ scale: 0.9, opacity: 0, y: 20 }}
                      animate={{ scale: 1, opacity: 1, y: 0 }}
                      className="bg-white rounded-[2.5rem] shadow-2xl w-full max-w-md overflow-hidden border border-slate-100"
                    >
                      <div className="p-8 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                        <div className="flex items-center gap-4">
                          <div className="p-3 bg-brand-50 rounded-2xl text-brand-600">
                            <Share2 className="w-6 h-6" />
                          </div>
                          <div>
                            <h3 className="text-xl font-display font-bold text-slate-900 tracking-tight">Share Access</h3>
                            <p className="text-xs text-slate-400 font-bold uppercase tracking-widest">Secure {sharingEntryId ? 'Entry' : 'File'}</p>
                          </div>
                        </div>
                        <button 
                          onClick={() => { setSharingEntryId(null); setSharingFileId(null); setShareEmail(''); }} 
                          className="p-2 text-slate-400 hover:text-slate-600 hover:bg-white rounded-xl transition-all"
                        >
                          <X className="w-6 h-6" />
                        </button>
                      </div>
                      <div className="p-8 space-y-6">
                        <p className="text-sm text-slate-500 leading-relaxed">
                          Enter the email address of the user you want to share this resource with. They must have a SecureVault account.
                        </p>
                        <div>
                          <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Recipient Email</label>
                          <div className="relative">
                            <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                            <input 
                              type="email" 
                              value={shareEmail}
                              onChange={(e) => setShareEmail(e.target.value)}
                              placeholder="colleague@company.com"
                              className="w-full pl-12 pr-6 py-4 rounded-2xl border border-slate-200 focus:ring-4 focus:ring-brand-500/10 focus:border-brand-500 outline-none transition-all font-medium text-slate-900"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-2">Access Level</label>
                          <div className="grid grid-cols-2 gap-4">
                            <button 
                              onClick={() => setShareAccessLevel('read')}
                              className={cn(
                                "py-4 rounded-2xl font-bold transition-all border-2 flex items-center justify-center gap-2",
                                shareAccessLevel === 'read' ? "bg-brand-50 border-brand-500 text-brand-600" : "bg-white border-slate-100 text-slate-400 hover:border-slate-200"
                              )}
                            >
                              <Eye className="w-4 h-4" />
                              Read Only
                            </button>
                            <button 
                              onClick={() => setShareAccessLevel('write')}
                              className={cn(
                                "py-4 rounded-2xl font-bold transition-all border-2 flex items-center justify-center gap-2",
                                shareAccessLevel === 'write' ? "bg-brand-50 border-brand-500 text-brand-600" : "bg-white border-slate-100 text-slate-400 hover:border-slate-200"
                              )}
                            >
                              <Lock className="w-4 h-4" />
                              Read & Write
                            </button>
                          </div>
                        </div>

                        {/* Existing Collaborators */}
                        <div className="pt-6 border-t border-slate-100">
                          <label className="block text-[10px] font-black text-slate-400 uppercase tracking-widest mb-4">Current Collaborators</label>
                          <div className="space-y-3 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
                            {(() => {
                              const resource = sharingEntryId 
                                ? entries.find(e => e.id === sharingEntryId)
                                : files.find(f => f.id === sharingFileId);
                              
                              if (!resource || !resource.sharedWith || resource.sharedWith.length === 0) {
                                return <p className="text-xs text-slate-400 italic">No one else has access yet.</p>;
                              }

                              return resource.sharedWith.map(uid => (
                                <div key={uid} className="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-100 group">
                                  <div className="flex items-center gap-3">
                                    <div className="w-8 h-8 rounded-full bg-slate-200 flex items-center justify-center text-[10px] font-black text-slate-500">
                                      {collaboratorEmails[uid]?.charAt(0).toUpperCase() || '?'}
                                    </div>
                                    <div>
                                      <p className="text-xs font-bold text-slate-700 truncate max-w-[120px]">{collaboratorEmails[uid] || 'Loading...'}</p>
                                      <p className="text-[9px] font-black text-slate-400 uppercase tracking-widest">
                                        {resource.permissions?.[uid] || 'read'} Access
                                      </p>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                    <button 
                                      onClick={() => updateAccessLevel(uid, resource.permissions?.[uid] === 'read' ? 'write' : 'read')}
                                      className="p-1.5 text-slate-400 hover:text-brand-600 hover:bg-white rounded-lg transition-all"
                                      title="Change Access"
                                    >
                                      {resource.permissions?.[uid] === 'read' ? <Lock className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                                    </button>
                                    <button 
                                      onClick={() => removeAccess(uid)}
                                      className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-white rounded-lg transition-all"
                                      title="Remove Access"
                                    >
                                      <Trash2 className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                </div>
                              ));
                            })()}
                          </div>
                        </div>
                      </div>
                      <div className="p-8 bg-slate-50 flex gap-4">
                        <button 
                          onClick={() => { setSharingEntryId(null); setSharingFileId(null); setShareEmail(''); }}
                          className="flex-1 py-4 text-slate-500 font-bold hover:bg-white rounded-2xl transition-all border border-transparent hover:border-slate-200"
                        >
                          Cancel
                        </button>
                        <button 
                          onClick={sharingEntryId ? shareEntry : shareFile}
                          className="flex-1 py-4 bg-brand-600 text-white font-bold hover:bg-brand-500 rounded-2xl transition-all shadow-xl shadow-brand-500/20 active:scale-95"
                        >
                          Grant Access
                        </button>
                      </div>
                    </motion.div>
                  </div>
                )}
              </motion.div>
            ) : activeTab === 'security' ? (
              <motion.div
                key="security"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-12"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h1 className="text-5xl font-display font-bold text-white tracking-tight">Security Settings</h1>
                    <p className="text-slate-400 mt-4 text-lg font-medium">Manage your account security and authentication methods.</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                  {/* 2FA Status Card */}
                  <div className="bg-slate-900/50 backdrop-blur-3xl rounded-[3rem] p-12 shadow-2xl border border-slate-800/50 flex flex-col items-center text-center">
                    <div className={cn(
                      "w-28 h-28 rounded-[2.5rem] flex items-center justify-center mb-10 shadow-2xl",
                      profile?.twoFactorEnabled ? "bg-green-500/10 text-green-400 shadow-green-500/20" : "bg-brand-500/10 text-brand-400 shadow-brand-500/20"
                    )}>
                      <ShieldCheck className="w-14 h-14" />
                    </div>
                    <h2 className="text-3xl font-display font-bold text-white mb-6">Two-Factor Authentication</h2>
                    <p className="text-slate-400 mb-12 leading-relaxed text-lg font-medium">
                      Protect your account with an extra layer of security. When enabled, you'll need to provide a code from your authenticator app to log in.
                    </p>
                    
                    {profile?.twoFactorEnabled ? (
                      <div className="w-full space-y-6">
                        <div className="bg-green-500/10 text-green-400 py-5 px-8 rounded-2xl font-black uppercase tracking-widest text-xs flex items-center justify-center gap-3 border border-green-500/20">
                          <ShieldCheck className="w-5 h-5" />
                          2FA is currently enabled
                        </div>
                        <button 
                          onClick={disable2FA}
                          className="w-full py-5 rounded-2xl font-black uppercase tracking-widest text-xs text-red-400 hover:bg-red-500/10 transition-all border border-red-500/20 active:scale-95"
                        >
                          Disable 2FA
                        </button>
                      </div>
                    ) : (
                      <button 
                        onClick={setup2FA}
                        className="w-full py-6 rounded-2xl font-black uppercase tracking-widest text-xs bg-brand-600 text-white hover:bg-brand-500 transition-all shadow-2xl shadow-brand-500/30 flex items-center justify-center gap-4 active:scale-95"
                      >
                        <Lock className="w-5 h-5" />
                        Enable 2FA
                      </button>
                    )}
                  </div>

                  {/* Security Info Card */}
                  <div className="bg-slate-950 rounded-[3rem] p-12 shadow-2xl text-white flex flex-col justify-between border border-slate-800/50 relative overflow-hidden">
                    <div className="absolute top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-brand-500/5 rounded-full blur-[80px]" />
                    <div className="relative z-10">
                      <div className="w-20 h-20 bg-brand-500/10 rounded-3xl flex items-center justify-center mb-10 border border-brand-500/20">
                        <Key className="w-10 h-10 text-brand-400" />
                      </div>
                      <h2 className="text-3xl font-display font-bold mb-8">Security Best Practices</h2>
                      <ul className="space-y-8">
                        <li className="flex gap-6">
                          <div className="w-8 h-8 bg-brand-600 rounded-xl flex-shrink-0 flex items-center justify-center text-xs font-black shadow-lg shadow-brand-600/20">1</div>
                          <p className="text-slate-400 text-base font-medium leading-relaxed">Use a strong, unique password for your SecureVault account.</p>
                        </li>
                        <li className="flex gap-6">
                          <div className="w-8 h-8 bg-brand-600 rounded-xl flex-shrink-0 flex items-center justify-center text-xs font-black shadow-lg shadow-brand-600/20">2</div>
                          <p className="text-slate-400 text-base font-medium leading-relaxed">Enable 2FA to prevent unauthorized access even if your password is compromised.</p>
                        </li>
                        <li className="flex gap-6">
                          <div className="w-8 h-8 bg-brand-600 rounded-xl flex-shrink-0 flex items-center justify-center text-xs font-black shadow-lg shadow-brand-600/20">3</div>
                          <p className="text-slate-400 text-base font-medium leading-relaxed">Regularly review your security logs for any suspicious activity.</p>
                        </li>
                      </ul>
                    </div>
                    <div className="mt-12 pt-12 border-t border-slate-800/50 relative z-10">
                      <p className="text-slate-500 text-[10px] uppercase tracking-[0.2em] font-black">Last Security Audit</p>
                      <p className="text-brand-400 font-mono mt-3 text-sm font-bold tracking-wider">March 24, 2026 - 15:28 UTC</p>
                    </div>
                  </div>
                </div>
              </motion.div>
            ) : (
              <motion.div 
                key="dashboard"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-12"
              >
                {/* Hero / Welcome Section */}
                <div className="relative overflow-hidden rounded-[3rem] bg-slate-950/50 backdrop-blur-3xl p-12 text-white shadow-2xl border border-slate-800/50">
                  <div className="absolute top-0 right-0 -mr-20 -mt-20 w-96 h-96 bg-brand-500/10 rounded-full blur-[120px] animate-pulse" />
                  <div className="absolute bottom-0 left-0 -ml-20 -mb-20 w-80 h-80 bg-brand-400/5 rounded-full blur-[100px]" />
                  
                  <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-12">
                    <div className="max-w-2xl text-center lg:text-left">
                      <div className="inline-flex items-center gap-2 px-4 py-2 bg-brand-500/10 rounded-full text-brand-400 text-[10px] font-black uppercase tracking-[0.2em] mb-6 border border-brand-500/20 backdrop-blur-sm">
                        <Zap className="w-3.5 h-3.5" />
                        System Status: Operational
                      </div>
                      <h1 className="text-5xl lg:text-7xl font-display font-bold mb-6 leading-tight tracking-tight">
                        Welcome back, <span className="text-brand-400">{user?.displayName?.split(' ')[0] || 'Agent'}</span>.
                      </h1>
                      <p className="text-slate-400 text-lg mb-10 leading-relaxed max-w-xl font-medium">
                        Your security perimeter is fully active. We've monitored <span className="text-white font-bold">{breachLogs.length} events</span> in the last 24 hours with no critical breaches detected.
                      </p>
                      <div className="flex flex-wrap justify-center lg:justify-start gap-5">
                        <button 
                          onClick={() => {
                            if (!profile?.twoFactorEnabled) {
                              setup2FA();
                            } else {
                              setActiveTab('vault');
                            }
                          }}
                          className="px-10 py-5 bg-brand-600 text-white font-black uppercase tracking-widest text-xs rounded-2xl hover:bg-brand-500 transition-all shadow-2xl shadow-brand-500/30 flex items-center gap-3 active:scale-95"
                        >
                          <ShieldCheck className="w-5 h-5" />
                          Get Started with College
                        </button>
                        <button 
                          onClick={() => setActiveTab('vault')}
                          className="px-10 py-5 bg-slate-800/50 text-white font-black uppercase tracking-widest text-xs rounded-2xl hover:bg-slate-700 transition-all border border-slate-700/50 backdrop-blur-md flex items-center gap-3 active:scale-95"
                        >
                          <Database className="w-5 h-5" />
                          Access Vault
                        </button>
                      </div>
                    </div>
                    
                    <div className="relative hidden lg:block">
                      <div className="w-72 h-72 bg-brand-500/10 rounded-full flex items-center justify-center animate-float-slow border border-brand-500/20">
                        <div className="w-56 h-56 bg-brand-500/20 rounded-full flex items-center justify-center border border-brand-500/20">
                          <div className="w-40 h-40 bg-slate-900 rounded-full flex items-center justify-center shadow-2xl shadow-brand-500/50 border border-brand-500/30">
                            <Shield className="w-20 h-20 text-brand-400" />
                          </div>
                        </div>
                      </div>
                      {/* Floating indicators */}
                      <div className="absolute -top-4 -right-4 bg-slate-900/80 backdrop-blur-xl p-4 rounded-2xl shadow-2xl border border-slate-800/50 animate-float" style={{ animationDelay: '1s' }}>
                        <div className="flex items-center gap-3">
                          <div className="w-2.5 h-2.5 bg-green-500 rounded-full shadow-[0_0_10px_rgba(34,197,94,0.5)]" />
                          <span className="text-[10px] font-black text-white uppercase tracking-widest">Live Monitoring</span>
                        </div>
                      </div>
                      <div className="absolute -bottom-4 -left-4 bg-slate-800 p-4 rounded-2xl shadow-xl border border-white/10 animate-float" style={{ animationDelay: '2s' }}>
                        <div className="flex items-center gap-3">
                          <TrendingUp className="w-4 h-4 text-brand-400" />
                          <span className="text-xs font-bold text-white">98% Health</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Main Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                  <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    className="stat-card bg-slate-900/40 backdrop-blur-xl border border-slate-800/50"
                  >
                    <div className="flex items-center justify-between mb-8">
                      <div className="p-4 bg-brand-500/10 text-brand-400 rounded-2xl border border-brand-500/20">
                        <Activity className="w-6 h-6" />
                      </div>
                      <div className="px-3 py-1 bg-green-500/10 text-green-400 border border-green-500/20 rounded-full text-[10px] font-black uppercase tracking-widest">
                        Optimal
                      </div>
                    </div>
                    <h3 className="text-slate-500 text-[10px] font-black uppercase tracking-[0.2em] mb-2">Security Health</h3>
                    <div className="text-4xl font-display font-bold text-white mb-4 tracking-tight">98.4%</div>
                    <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: '98.4%' }}
                        transition={{ duration: 1, delay: 0.5 }}
                        className="bg-brand-500 h-full rounded-full shadow-[0_0_15px_rgba(51,85,255,0.5)]" 
                      />
                    </div>
                  </motion.div>

                  <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                    whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    className="stat-card bg-slate-900/40 backdrop-blur-xl border border-slate-800/50"
                  >
                    <div className="flex items-center justify-between mb-8">
                      <div className="p-4 bg-brand-500/10 text-brand-400 rounded-2xl border border-brand-500/20">
                        <Database className="w-6 h-6" />
                      </div>
                    </div>
                    <h3 className="text-slate-500 text-[10px] font-black uppercase tracking-[0.2em] mb-2">Total Events</h3>
                    <div className="text-4xl font-display font-bold text-white mb-4 tracking-tight">{breachLogs.length}</div>
                    <p className="text-slate-500 text-[10px] font-black uppercase tracking-widest">System-wide monitoring active</p>
                  </motion.div>

                  <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    className="stat-card bg-slate-900/40 backdrop-blur-xl border border-slate-800/50"
                  >
                    <div className="flex items-center justify-between mb-8">
                      <div className="p-4 bg-red-500/10 text-red-400 rounded-2xl border border-red-500/20">
                        <ShieldAlert className="w-6 h-6" />
                      </div>
                      <div className="px-3 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded-full text-[10px] font-black uppercase tracking-widest">
                        Alert
                      </div>
                    </div>
                    <h3 className="text-slate-500 text-[10px] font-black uppercase tracking-[0.2em] mb-2">High Severity</h3>
                    <div className="text-4xl font-display font-bold text-red-500 mb-4 tracking-tight">
                      {breachLogs.filter(l => l.severity === 'high').length}
                    </div>
                    <p className="text-slate-500 text-[10px] font-black uppercase tracking-widest">Requires immediate attention</p>
                  </motion.div>

                  <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                    whileHover={{ y: -5, transition: { duration: 0.2 } }}
                    className="stat-card bg-brand-600 text-white"
                  >
                    <div className="absolute top-0 right-0 -mr-8 -mt-8 w-32 h-32 bg-white/10 rounded-full blur-2xl" />
                    <div className="flex items-center justify-between mb-8">
                      <div className="p-4 bg-white/10 rounded-2xl">
                        <Lock className="w-6 h-6 text-white" />
                      </div>
                    </div>
                    <h3 className="text-white/60 text-xs font-black uppercase tracking-widest mb-2">2FA Status</h3>
                    <div className="text-4xl font-display font-bold mb-4 tracking-tight">
                      {profile?.twoFactorEnabled ? 'Active' : 'Inactive'}
                    </div>
                    <button 
                      onClick={() => setActiveTab('security')}
                      className="text-xs font-bold text-brand-200 hover:text-white transition-colors flex items-center gap-1"
                    >
                      Manage Security <ChevronRight className="w-3 h-3" />
                    </button>
                  </motion.div>
                </div>

                {/* Dashboard Main Content */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-10">
                  {/* Chart Section */}
                  <div className="bento-item lg:col-span-2">
                    <div className="flex items-center justify-between mb-10">
                      <div>
                        <h3 className="text-2xl font-display font-bold text-white tracking-tight">Threat Intelligence</h3>
                        <p className="text-slate-500 text-sm mt-1">Real-time analysis of security events across your perimeter.</p>
                      </div>
                      <div className="flex items-center gap-2 p-1 bg-slate-950/50 rounded-xl border border-slate-800/50">
                        <button className="px-4 py-2 bg-slate-800 text-white rounded-lg shadow-sm text-[10px] font-black uppercase tracking-widest">24h</button>
                        <button className="px-4 py-2 text-[10px] font-black text-slate-500 hover:text-white uppercase tracking-widest transition-colors">7d</button>
                        <button className="px-4 py-2 text-[10px] font-black text-slate-500 hover:text-white uppercase tracking-widest transition-colors">30d</button>
                      </div>
                    </div>
                    <div className="h-80 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={timelineData}>
                          <defs>
                            <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#3355ff" stopOpacity={0.3}/>
                              <stop offset="95%" stopColor="#3355ff" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1e293b" />
                          <XAxis 
                            dataKey="date" 
                            axisLine={false} 
                            tickLine={false} 
                            tick={{ fill: '#94a3b8', fontSize: 10, fontWeight: 700 }}
                            dy={10}
                          />
                          <YAxis 
                            axisLine={false} 
                            tickLine={false} 
                            tick={{ fill: '#94a3b8', fontSize: 10, fontWeight: 700 }}
                          />
                          <Tooltip 
                            contentStyle={{ 
                              backgroundColor: '#0f172a', 
                              border: 'none', 
                              borderRadius: '16px', 
                              color: '#fff',
                              boxShadow: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)'
                            }}
                            itemStyle={{ color: '#fff', fontSize: '12px', fontWeight: 'bold' }}
                            labelStyle={{ color: '#94a3b8', fontSize: '10px', marginBottom: '4px', textTransform: 'uppercase', fontWeight: '900' }}
                          />
                          <Area 
                            type="monotone" 
                            dataKey="count" 
                            stroke="#3355ff" 
                            strokeWidth={4}
                            fillOpacity={1} 
                            fill="url(#colorEvents)" 
                            isAnimationActive={true}
                            animationDuration={1500}
                            animationEasing="ease-in-out"
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Quick Actions & Recent Activity */}
                  <div className="space-y-10">
                    <div className="bento-item">
                      <h3 className="text-xl font-display font-bold text-white mb-6 tracking-tight">Quick Actions</h3>
                      <div className="grid grid-cols-2 gap-4">
                        <motion.button 
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          onClick={() => { setActiveTab('storage'); setStorageSubTab('entries'); setShowNewForm(true); }}
                          className="p-6 bg-slate-950/30 rounded-3xl border border-slate-800/50 hover:border-brand-500/30 hover:bg-brand-500/5 transition-all group text-left"
                        >
                          <div className="w-10 h-10 bg-slate-800 rounded-xl flex items-center justify-center mb-4 shadow-sm group-hover:bg-brand-500 group-hover:text-white transition-all">
                            <Plus className="w-5 h-5" />
                          </div>
                          <span className="text-sm font-bold text-white block group-hover:text-brand-400 transition-colors">New Entry</span>
                          <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest">Secure Data</span>
                        </motion.button>
                        <motion.button 
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          onClick={() => { setActiveTab('storage'); setStorageSubTab('files'); setShowUploadForm(true); }}
                          className="p-6 bg-slate-950/30 rounded-3xl border border-slate-800/50 hover:border-brand-500/30 hover:bg-brand-500/5 transition-all group text-left"
                        >
                          <div className="w-10 h-10 bg-slate-800 rounded-xl flex items-center justify-center mb-4 shadow-sm group-hover:bg-brand-500 group-hover:text-white transition-all">
                            <Upload className="w-5 h-5" />
                          </div>
                          <span className="text-sm font-bold text-white block group-hover:text-brand-400 transition-colors">Upload File</span>
                          <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest">Encrypted</span>
                        </motion.button>
                        <motion.button 
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          onClick={() => setActiveTab('security')}
                          className="p-6 bg-slate-950/30 rounded-3xl border border-slate-800/50 hover:border-brand-500/30 hover:bg-brand-500/5 transition-all group text-left"
                        >
                          <div className="w-10 h-10 bg-slate-800 rounded-xl flex items-center justify-center mb-4 shadow-sm group-hover:bg-brand-500 group-hover:text-white transition-all">
                            <ShieldCheck className="w-5 h-5" />
                          </div>
                          <span className="text-sm font-bold text-white block group-hover:text-brand-400 transition-colors">Security</span>
                          <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest">Manage 2FA</span>
                        </motion.button>
                        <motion.button 
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          onClick={() => { setActiveTab('storage'); setStorageSubTab('entries'); }}
                          className="p-6 bg-slate-950/30 rounded-3xl border border-slate-800/50 hover:border-brand-500/30 hover:bg-brand-500/5 transition-all group text-left"
                        >
                          <div className="w-10 h-10 bg-slate-800 rounded-xl flex items-center justify-center mb-4 shadow-sm group-hover:bg-brand-500 group-hover:text-white transition-all">
                            <Share2 className="w-5 h-5" />
                          </div>
                          <span className="text-sm font-bold text-white block group-hover:text-brand-400 transition-colors">Sharing</span>
                          <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest">Permissions</span>
                        </motion.button>
                      </div>
                    </div>

                    <div className="bento-item">
                      <div className="flex items-center justify-between mb-6">
                        <h3 className="text-xl font-display font-bold text-white tracking-tight">Recent Logs</h3>
                        <button className="text-[10px] font-black text-brand-400 uppercase tracking-widest hover:text-brand-300 transition-colors">View All</button>
                      </div>
                      <div className="space-y-6">
                        {breachLogs.slice(0, 4).map((log, idx) => (
                          <div key={log.id} className="flex items-start gap-4 group cursor-pointer">
                            <div className={cn(
                              "w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 shadow-lg",
                              log.severity === 'high' ? 'bg-red-500 shadow-red-500/40' : log.severity === 'medium' ? 'bg-amber-500 shadow-amber-500/40' : 'bg-green-500 shadow-green-500/40'
                            )} />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-bold text-white truncate group-hover:text-brand-400 transition-colors">{log.type}</p>
                              <div className="flex items-center gap-2 mt-1.5">
                                <Clock className="w-3.5 h-3.5 text-slate-500" />
                                <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest">
                                  {log.timestamp?.toDate()?.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) || 'Recently'}
                                </span>
                              </div>
                            </div>
                            <div className={cn(
                              "text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-md border",
                              log.severity === 'high' ? 'text-red-400 border-red-500/20 bg-red-500/5' : 
                              log.severity === 'medium' ? 'text-amber-400 border-amber-500/20 bg-amber-500/5' : 
                              'text-green-400 border-green-500/20 bg-green-500/5'
                            )}>
                              {log.severity}
                            </div>
                          </div>
                        ))}
                        {breachLogs.length === 0 && (
                          <div className="flex flex-col items-center gap-3 py-8 opacity-30">
                            <ShieldCheck className="w-8 h-8 text-slate-500" />
                            <p className="text-slate-500 text-[10px] font-black uppercase tracking-widest text-center">No recent activity logs.</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Testing & Simulation Section */}
                <motion.div 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.5 }}
                  className="bg-slate-900 rounded-[2.5rem] p-10 text-white overflow-hidden relative"
                >
                  <div className="absolute top-0 right-0 p-12 opacity-10">
                    <Bug className="w-48 h-48" />
                  </div>
                  <div className="relative z-10">
                    <div className="flex items-center gap-4 mb-8">
                      <div className="p-3 bg-white/10 rounded-2xl">
                        <Bug className="w-6 h-6 text-brand-400" />
                      </div>
                      <div>
                        <h3 className="text-2xl font-display font-bold tracking-tight">Testing & Simulation</h3>
                        <p className="text-slate-400 text-sm">Use these tools to verify the platform's real-time features and security alerting.</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                      <button 
                        onClick={simulateSecurityAlert}
                        className="p-6 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl transition-all text-left group"
                      >
                        <ShieldAlert className="w-8 h-8 text-red-400 mb-4 group-hover:scale-110 transition-transform" />
                        <h4 className="font-bold mb-1">Simulate Threat</h4>
                        <p className="text-xs text-slate-400">Trigger a high-severity security alert and notification.</p>
                      </button>
                      <button 
                        onClick={seedSampleData}
                        className="p-6 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl transition-all text-left group"
                      >
                        <Database className="w-8 h-8 text-brand-400 mb-4 group-hover:scale-110 transition-transform" />
                        <h4 className="font-bold mb-1">Seed Sample Data</h4>
                        <p className="text-xs text-slate-400">Populate your vault with encrypted test entries and files.</p>
                      </button>
                      <button 
                        onClick={sendTestNotification}
                        className="p-6 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl transition-all text-left group"
                      >
                        <Bell className="w-8 h-8 text-amber-400 mb-4 group-hover:scale-110 transition-transform" />
                        <h4 className="font-bold mb-1">Test Notification</h4>
                        <p className="text-xs text-slate-400">Send a real-time system notification to your account.</p>
                      </button>
                    </div>
                  </div>
                </motion.div>

                {/* Recent Logs Table */}
                <motion.div 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.6 }}
                  className="bg-slate-900/40 backdrop-blur-2xl rounded-[2.5rem] border border-slate-800/50 shadow-2xl overflow-hidden"
                >
                  <div className="p-8 border-b border-slate-800/50 flex items-center justify-between bg-slate-950/30">
                    <h3 className="text-2xl font-display font-bold text-white tracking-tight">Recent Security Logs</h3>
                    <button className="text-brand-400 text-[10px] font-black hover:text-brand-300 uppercase tracking-[0.2em] transition-colors">View All Logs</button>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-950/50">
                          <th className="px-8 py-6 text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Timestamp</th>
                          <th className="px-8 py-6 text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Event Type</th>
                          <th className="px-8 py-6 text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Severity</th>
                          <th className="px-8 py-6 text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Status</th>
                          <th className="px-8 py-6 text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/50">
                        {breachLogs.slice(0, 5).map((log) => (
                          <tr key={log.id} className="hover:bg-white/5 transition-all duration-300 group">
                            <td className="px-8 py-7 text-sm text-slate-400 font-medium">
                              {log.timestamp?.toDate()?.toLocaleString() || 'Recently'}
                            </td>
                            <td className="px-8 py-7">
                              <div className="text-base font-bold text-white mb-1">{log.type}</div>
                              <div className="text-xs text-slate-500 font-medium">{log.description}</div>
                            </td>
                            <td className="px-8 py-7">
                              <span className={cn(
                                "px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-widest border",
                                log.severity === 'high' ? "bg-red-500/10 text-red-400 border-red-500/20 shadow-[0_0_15px_-3px_rgba(239,68,68,0.2)]" :
                                log.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20 shadow-[0_0_15px_-3px_rgba(245,158,11,0.2)]" :
                                "bg-green-500/10 text-green-400 border-green-500/20 shadow-[0_0_15px_-3px_rgba(34,197,94,0.2)]"
                              )}>
                                {log.severity}
                              </span>
                            </td>
                            <td className="px-8 py-7">
                              <div className="flex items-center gap-3 text-[10px] font-black text-slate-400 uppercase tracking-widest">
                                <div className={cn(
                                  "w-2.5 h-2.5 rounded-full shadow-lg",
                                  log.status === 'blocked' ? "bg-red-500 shadow-red-500/40" :
                                  log.status === 'flagged' ? "bg-amber-500 shadow-amber-500/40" :
                                  "bg-green-500 shadow-green-500/40"
                                )} />
                                {log.status || 'Logged'}
                              </div>
                            </td>
                            <td className="px-8 py-7 text-right">
                              <div className="flex items-center justify-end gap-3 opacity-0 group-hover:opacity-100 transition-all translate-x-4 group-hover:translate-x-0">
                                <button 
                                  onClick={() => setInvestigatingLogId(log.id)}
                                  className="px-5 py-2.5 bg-brand-600 text-white text-[10px] font-black uppercase tracking-widest rounded-xl hover:bg-brand-500 transition-all shadow-lg shadow-brand-500/20 active:scale-95"
                                >
                                  Investigate
                                </button>
                                <button className="p-2.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition-all active:scale-90">
                                  <Trash2 className="w-5 h-5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                        {breachLogs.length === 0 && (
                          <tr>
                            <td colSpan={5} className="px-8 py-24 text-center">
                              <div className="flex flex-col items-center gap-4 opacity-30">
                                <ShieldCheck className="w-12 h-12 text-slate-500" />
                                <p className="text-slate-500 text-xs font-black uppercase tracking-[0.2em]">
                                  No security events logged in the last 24 hours.
                                </p>
                              </div>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>

        {/* Footer */}
        <footer className="bg-white border-t border-slate-200 py-12">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="flex items-center gap-4">
                <div className="p-2 bg-slate-100 rounded-xl">
                  <Shield className="w-5 h-5 text-slate-400" />
                </div>
                <div>
                  <p className="text-sm font-bold text-slate-900">SecureVault Business</p>
                  <p className="text-xs text-slate-400 font-medium">© 2026 Enterprise Data Security. All rights reserved.</p>
                </div>
              </div>
              <div className="flex items-center gap-8 text-[10px] font-black text-slate-400 uppercase tracking-widest">
                <a href="#" className="hover:text-brand-600 transition-colors">Privacy Policy</a>
                <a href="#" className="hover:text-brand-600 transition-colors">Security Audit</a>
                <a href="#" className="hover:text-brand-600 transition-colors">Compliance</a>
                <a href="#" className="hover:text-brand-600 transition-colors">Support</a>
              </div>
            </div>
          </div>
        </footer>

        {/* 2FA Setup Modal */}
        {show2FASetup && (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-md z-[60] flex items-center justify-center p-4">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              className="bg-white rounded-[2.5rem] shadow-2xl w-full max-w-lg overflow-hidden border border-slate-100"
            >
              <div className="p-8 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                <div className="flex items-center gap-4">
                  <div className="p-3 bg-brand-50 rounded-2xl text-brand-600">
                    <ShieldCheck className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-xl font-display font-bold text-slate-900 tracking-tight">Setup 2FA</h3>
                    <p className="text-xs text-slate-400 font-bold uppercase tracking-widest">Enhanced Security</p>
                  </div>
                </div>
                <button 
                  onClick={() => setShow2FASetup(false)} 
                  className="p-2 text-slate-400 hover:text-slate-600 hover:bg-white rounded-xl transition-all"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>
              
              <div className="p-8 space-y-8 max-h-[70vh] overflow-y-auto">
                <div className="space-y-4">
                  <p className="text-slate-600 leading-relaxed">
                    1. Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
                  </p>
                  <div className="flex justify-center p-6 bg-slate-50 rounded-3xl border border-slate-100">
                    <QRCodeCanvas value={qrCodeUrl} size={200} />
                  </div>
                </div>

                <div className="space-y-4">
                  <p className="text-slate-600 leading-relaxed">
                    2. Enter the 6-digit code from the app to verify setup
                  </p>
                  <input 
                    type="text"
                    maxLength={6}
                    value={twoFactorCode}
                    onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000000"
                    className="w-full text-center text-3xl font-mono tracking-[0.5em] py-5 rounded-2xl border border-slate-200 focus:ring-4 focus:ring-brand-500/10 focus:border-brand-500 outline-none transition-all"
                  />
                  {twoFactorError && <p className="text-red-500 text-sm font-bold">{twoFactorError}</p>}
                </div>
              </div>

              <div className="p-8 bg-slate-50 flex gap-4">
                <button 
                  onClick={() => setShow2FASetup(false)}
                  className="flex-1 py-4 text-slate-500 font-bold hover:bg-white rounded-2xl transition-all border border-transparent hover:border-slate-200"
                >
                  Cancel
                </button>
                <button 
                  onClick={verifyAndEnable2FA}
                  disabled={twoFactorCode.length !== 6 || isVerifying2FA}
                  className={cn(
                    "flex-1 py-4 font-bold rounded-2xl transition-all shadow-xl flex items-center justify-center gap-2",
                    twoFactorCode.length === 6 && !isVerifying2FA ? "bg-brand-600 text-white hover:bg-brand-500 shadow-brand-500/20" : "bg-slate-200 text-slate-400 cursor-not-allowed"
                  )}
                >
                  {isVerifying2FA ? (
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <>
                      <Check className="w-5 h-5" />
                      Complete Setup
                    </>
                  )}
                </button>
              </div>
            </motion.div>
          </div>
        )}
        {/* Investigation Modal */}
        {investigatingLogId && (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-md z-[70] flex items-center justify-center p-4">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              className="bg-slate-900 rounded-[2.5rem] shadow-2xl w-full max-w-2xl overflow-hidden border border-slate-800"
            >
              {(() => {
                const log = breachLogs.find(l => l.id === investigatingLogId);
                if (!log) return null;
                return (
                  <>
                    <div className="p-8 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
                      <div className="flex items-center gap-4">
                        <div className={cn(
                          "p-3 rounded-2xl",
                          log.severity === 'high' ? "bg-red-500/10 text-red-400" :
                          log.severity === 'medium' ? "bg-amber-500/10 text-amber-400" :
                          "bg-blue-500/10 text-blue-400"
                        )}>
                          <ShieldAlert className="w-6 h-6" />
                        </div>
                        <div>
                          <h3 className="text-xl font-display font-bold text-white tracking-tight">Investigation Report</h3>
                          <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">Event ID: {log.id.slice(0, 8)}</p>
                        </div>
                      </div>
                      <button 
                        onClick={() => setInvestigatingLogId(null)} 
                        className="p-2 text-slate-500 hover:text-white hover:bg-slate-800 rounded-xl transition-all"
                      >
                        <X className="w-6 h-6" />
                      </button>
                    </div>
                    
                    <div className="p-8 space-y-8 max-h-[70vh] overflow-y-auto">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div className="space-y-6">
                          <div>
                            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Event Details</h4>
                            <div className="p-6 bg-slate-800/50 rounded-3xl border border-slate-700/50 space-y-4">
                              <div>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Type</p>
                                <p className="text-sm font-bold text-white">{log.type}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Timestamp</p>
                                <p className="text-sm font-bold text-white">{log.timestamp?.toDate()?.toLocaleString()}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Severity</p>
                                <span className={cn(
                                  "px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-widest inline-block mt-1",
                                  log.severity === 'high' ? "bg-red-500/20 text-red-400" :
                                  log.severity === 'medium' ? "bg-amber-500/20 text-amber-400" :
                                  "bg-blue-500/20 text-blue-400"
                                )}>
                                  {log.severity}
                                </span>
                              </div>
                            </div>
                          </div>

                          <div>
                            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">System Response</h4>
                            <div className="p-6 bg-slate-800/50 rounded-3xl border border-slate-700/50">
                              <div className="flex items-center gap-3">
                                <div className={cn(
                                  "w-3 h-3 rounded-full",
                                  log.status === 'blocked' ? "bg-red-500" :
                                  log.status === 'flagged' ? "bg-amber-500" :
                                  "bg-green-500"
                                )} />
                                <p className="text-sm font-bold text-white uppercase tracking-widest">{log.status || 'LOGGED'}</p>
                              </div>
                              <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                                {log.status === 'blocked' ? "The connection was immediately terminated and the source IP was added to the blacklist." :
                                 log.status === 'flagged' ? "The event was flagged for manual review and the user session was restricted." :
                                 "The event was recorded in the system audit logs for future reference."}
                              </p>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-6">
                          <div>
                            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Source Metadata</h4>
                            <div className="p-6 bg-slate-800/50 rounded-3xl border border-slate-700/50 space-y-4">
                              <div>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">IP Address</p>
                                <p className="text-sm font-mono font-bold text-white">{log.ipAddress || 'Unknown'}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Location</p>
                                <p className="text-sm font-bold text-white">{log.location || 'Unknown'}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Target Resource</p>
                                <p className="text-sm font-mono text-xs font-bold text-white break-all">{log.resource || 'N/A'}</p>
                              </div>
                            </div>
                          </div>

                          <div>
                            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">User Agent</h4>
                            <div className="p-6 bg-slate-800/50 rounded-3xl border border-slate-700/50">
                              <p className="text-[10px] font-mono text-slate-400 break-all leading-relaxed">
                                {log.userAgent || 'No user agent data available.'}
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="p-6 bg-slate-950 rounded-3xl text-white border border-slate-800">
                        <div className="flex items-center gap-3 mb-4">
                          <Terminal className="w-5 h-5 text-brand-400" />
                          <h4 className="text-sm font-bold uppercase tracking-widest">Analyst Description</h4>
                        </div>
                        <p className="text-sm text-slate-300 leading-relaxed italic">
                          "{log.description}"
                        </p>
                      </div>
                    </div>

                    <div className="p-8 bg-slate-950/50 border-t border-slate-800 flex justify-end gap-4">
                      <button 
                        onClick={() => setInvestigatingLogId(null)}
                        className="px-6 py-3 bg-slate-800 text-white text-sm font-bold rounded-2xl hover:bg-slate-700 transition-all border border-slate-700/50"
                      >
                        Close Report
                      </button>
                      <button 
                        className="px-6 py-3 bg-brand-600 text-white text-sm font-bold rounded-2xl hover:bg-brand-500 transition-all flex items-center gap-2 shadow-lg shadow-brand-500/20"
                      >
                        <Download className="w-4 h-4" /> Export PDF
                      </button>
                    </div>
                  </>
                );
              })()}
            </motion.div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
