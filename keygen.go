import 'dart:convert';
import 'dart:async'; 
import 'package:flutter/material.dart';
import 'package:flutter/services.dart'; 
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:uuid/uuid.dart'; 
import 'package:intl/intl.dart'; 
import 'package:image_picker/image_picker.dart'; 
import 'package:overlay_support/overlay_support.dart';
import 'package:google_fonts/google_fonts.dart';

const storage = FlutterSecureStorage();
const uuid = Uuid(); 

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  try {
    await Hive.initFlutter();
    await Hive.openBox('chat_history'); 
    await Hive.openBox('contacts');     
    await Hive.openBox('blocked_users'); 
    await Hive.openBox('avatars'); 
    await Hive.openBox('settings');
  } catch (e) {
    debugPrint("Database initialization failed: $e");
  }
  
  runApp(const WingsConnectApp());
}

class WingsConnectApp extends StatelessWidget {
  const WingsConnectApp({super.key});

  Future<Map<String, dynamic>?> checkExistingLogin() async {
    try {
      final isLoggedIn = await storage.read(key: "is_logged_in");
      final savedWingId = await storage.read(key: "wing_id");
      final savedPrivateKey = await storage.read(key: "private_key");
      final savedPublicKey = await storage.read(key: "public_key"); 

      if (isLoggedIn == "true" && savedWingId != null && savedPrivateKey != null && savedPublicKey != null) {
        final privateBytes = base64Decode(savedPrivateKey);
        final publicBytes = base64Decode(savedPublicKey);

        final keyPair = SimpleKeyPairData(
          privateBytes,
          publicKey: SimplePublicKey(publicBytes, type: KeyPairType.x25519), 
          type: KeyPairType.x25519,
        );
        
        return {
          "wingId": savedWingId,
          "keyPair": keyPair,
        };
      }
    } catch (e) {
      debugPrint("Secure storage read error: $e");
    }
    return null; 
  }

  @override
  Widget build(BuildContext context) {
    return OverlaySupport.global(
      child: MaterialApp(
        title: 'Connect by Wings',
        debugShowCheckedModeBanner: false, 
        theme: ThemeData.dark().copyWith(
          primaryColor: Colors.blueAccent,
          scaffoldBackgroundColor: const Color(0xFF0A0A0A),
          textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme).apply(
            bodyColor: Colors.white,
            displayColor: Colors.white,
          ),
          appBarTheme: const AppBarTheme(
            backgroundColor: Color(0xFF141414),
            elevation: 0,
            centerTitle: true,
          ),
          inputDecorationTheme: InputDecorationTheme(
            filled: true,
            fillColor: const Color(0xFF141414), 
            contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 18),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide.none),
            enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide(color: Colors.white.withOpacity(0.05))),
            focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: const BorderSide(color: Colors.blueAccent, width: 1.5)),
            labelStyle: const TextStyle(color: Colors.white54, fontSize: 14),
            hintStyle: const TextStyle(color: Colors.white38, fontSize: 14),
          ),
        ),
        home: FutureBuilder<Map<String, dynamic>?>(
          future: checkExistingLogin(),
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const Scaffold(body: Center(child: CircularProgressIndicator(color: Colors.blueAccent)));
            }
            if (snapshot.hasData && snapshot.data != null) {
              return DashboardScreen(
                myWingId: snapshot.data!["wingId"],
                myKeyPair: snapshot.data!["keyPair"],
              );
            } else {
              return const AuthScreen();
            }
          },
        ),
      ),
    );
  }
}

// ==========================================
// 1. THE AUTHENTICATION SCREEN
// ==========================================
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});
  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final TextEditingController _usernameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController(); 
  final TextEditingController _emailController = TextEditingController();    
  bool _isLoading = false;
  bool _isLoginMode = true; 
  final x25519 = X25519();

  void showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message, style: const TextStyle(color: Colors.white)), backgroundColor: Colors.redAccent));
  }

  Future<void> submitAuth() async {
    final username = _usernameController.text.trim();
    final password = _passwordController.text.trim();
    final email = _emailController.text.trim();

    if (username.isEmpty || password.isEmpty) {
      showError("Username and Password are required.");
      return;
    }
    if (!_isLoginMode && email.isEmpty) {
      showError("Recovery Email is required for registration.");
      return;
    }

    setState(() => _isLoading = true);

    try {
      String wingId = "";

      if (_isLoginMode) {
        final res = await http.post(
          Uri.parse("http://192.168.1.49:8080/login"), 
          headers: {"Content-Type": "application/json"},
          body: jsonEncode({"username": username, "password": password}), 
        );
        if (res.statusCode == 200) {
          wingId = jsonDecode(res.body)["wing_id"];
        } else {
          showError("Invalid Username or Password.");
          setState(() => _isLoading = false);
          return;
        }
      } else {
        final res = await http.post(
          Uri.parse("http://192.168.1.49:8080/register"), 
          headers: {"Content-Type": "application/json"},
          body: jsonEncode({"username": username, "password": password, "email": email}), 
        );
        if (res.statusCode == 200) {
          wingId = jsonDecode(res.body)["wing_id"];
        } else {
          showError("Username already exists.");
          setState(() => _isLoading = false);
          return;
        }
      }

      final keyPair = await x25519.newKeyPair();
      final publicKeyBase64 = base64Encode((await keyPair.extractPublicKey()).bytes);
      final privateKeyBase64 = base64Encode(await keyPair.extractPrivateKeyBytes());

      await http.post(
        Uri.parse("http://192.168.1.49:8080/upload-key"),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({"wing_id": wingId, "public_key": publicKeyBase64}),
      );

      final previousWingId = await storage.read(key: "wing_id");
      if (previousWingId != null && previousWingId != wingId) {
        await Hive.box('chat_history').clear();
        await Hive.box('contacts').clear();
        await Hive.box('blocked_users').clear();
        await Hive.box('avatars').clear();
        await Hive.box('settings').clear();
      }

      await storage.write(key: "is_logged_in", value: "true"); 
      await storage.write(key: "wing_id", value: wingId);
      await storage.write(key: "private_key", value: privateKeyBase64);
      await storage.write(key: "public_key", value: publicKeyBase64); 

      if (mounted) {
        Navigator.pushReplacement(context, MaterialPageRoute(builder: (context) => DashboardScreen(myWingId: wingId, myKeyPair: keyPair)));
      }
    } catch (e) {
      showError("Connection error. Is the server running?");
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _showForgotPasswordDialog() {
    final resetUserCtrl = TextEditingController();
    final resetEmailCtrl = TextEditingController();
    final resetNewPassCtrl = TextEditingController();
    
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        title: const Text("Reset Password", style: TextStyle(fontWeight: FontWeight.w800)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text("Enter your account details to securely reset your password.", style: TextStyle(fontSize: 13, color: Colors.white54, height: 1.4)),
            const SizedBox(height: 20),
            TextField(controller: resetUserCtrl, decoration: const InputDecoration(labelText: "Username")),
            const SizedBox(height: 12),
            TextField(controller: resetEmailCtrl, keyboardType: TextInputType.emailAddress, decoration: const InputDecoration(labelText: "Recovery Email")),
            const SizedBox(height: 12),
            TextField(controller: resetNewPassCtrl, obscureText: true, decoration: const InputDecoration(labelText: "New Password")),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel", style: TextStyle(color: Colors.white54))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            onPressed: () async {
              if (resetUserCtrl.text.isEmpty || resetEmailCtrl.text.isEmpty || resetNewPassCtrl.text.isEmpty) return;
              try {
                final res = await http.post(
                  Uri.parse("http://192.168.1.49:8080/reset-password"),
                  headers: {"Content-Type": "application/json"},
                  body: jsonEncode({"username": resetUserCtrl.text, "email": resetEmailCtrl.text, "new_password": resetNewPassCtrl.text})
                );
                if (res.statusCode == 200) {
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Password reset successfully! You can now log in.")));
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Invalid Username or Email.", style: TextStyle(color: Colors.white)), backgroundColor: Colors.redAccent));
                }
              } catch (e) { ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Network error."))); }
            },
            child: const Text("Reset", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
          )
        ]
      )
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        // The deep radial background gradient
        decoration: const BoxDecoration(
          gradient: RadialGradient(
            center: Alignment(0.0, -0.6), 
            radius: 0.8,
            colors: [Color(0xFF0F1B2E), Color(0xFF0A0A0A)], 
          )
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 32.0),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const WingsLogo(size: 180),
                  const SizedBox(height: 24),
                  const Text("Connect", textAlign: TextAlign.center, style: TextStyle(fontSize: 36, fontWeight: FontWeight.w900, letterSpacing: -1.2)),
                  const Text("BY WINGS", textAlign: TextAlign.center, style: TextStyle(fontSize: 12, color: Colors.blueAccent, letterSpacing: 4.0, fontWeight: FontWeight.w800)),
                  const SizedBox(height: 48),
                  
                  TextField(controller: _usernameController, decoration: const InputDecoration(labelText: "Username")),
                  
                  AnimatedSize(
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeInOut,
                    child: !_isLoginMode 
                      ? Padding(
                          padding: const EdgeInsets.only(top: 16),
                          child: TextField(controller: _emailController, keyboardType: TextInputType.emailAddress, decoration: const InputDecoration(labelText: "Recovery Email")),
                        )
                      : const SizedBox.shrink(),
                  ),
                  
                  const SizedBox(height: 16),
                  TextField(controller: _passwordController, obscureText: true, decoration: const InputDecoration(labelText: "Password")),
                  const SizedBox(height: 32),
                  
                  _isLoading 
                    ? const Center(child: CircularProgressIndicator(color: Colors.blueAccent)) 
                    : Container(
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(16),
                          gradient: const LinearGradient(
                            colors: [Color(0xFF00C6FF), Color(0xFF0072FF)], 
                            begin: Alignment.centerLeft,
                            end: Alignment.centerRight,
                          ),
                          boxShadow: [
                            BoxShadow(color: Colors.blueAccent.withOpacity(0.3), blurRadius: 12, offset: const Offset(0, 6))
                          ]
                        ),
                        child: ElevatedButton(
                          onPressed: submitAuth, 
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.transparent, 
                            shadowColor: Colors.transparent, 
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(vertical: 18), 
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))
                          ), 
                          child: Text(_isLoginMode ? "Secure Login" : "Create Account", style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold))
                        ),
                      ),
                  
                  const SizedBox(height: 24),
                  
                  TextButton(
                    onPressed: () => setState(() => _isLoginMode = !_isLoginMode), 
                    child: Text(_isLoginMode ? "Need an account? Register" : "Already have an account? Login", style: const TextStyle(color: Colors.white70, fontWeight: FontWeight.w600))
                  ),
                  
                  if (_isLoginMode)
                    TextButton(
                      onPressed: _showForgotPasswordDialog, 
                      child: const Text("Forgot Password?", style: TextStyle(color: Colors.blueAccent, fontWeight: FontWeight.bold))
                    )
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ==========================================
// 2. THE DASHBOARD / CHAT SCREEN
// ==========================================
class DashboardScreen extends StatefulWidget {
  final String myWingId;
  final SimpleKeyPair myKeyPair;

  const DashboardScreen({super.key, required this.myWingId, required this.myKeyPair});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final TextEditingController _msgController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final ImagePicker _picker = ImagePicker(); 
  
  final _chatBox = Hive.box('chat_history');
  final _contactsBox = Hive.box('contacts');
  final _blockedBox = Hive.box('blocked_users');
  final _avatarsBox = Hive.box('avatars'); 
  final _settingsBox = Hive.box('settings'); 

  String? activeContactId;
  String? activeContactName;

  late WebSocketChannel channel;
  final x25519 = X25519();
  final aes = AesGcm.with256bits();

  bool _isFriendTyping = false;
  Timer? _typingTimer;
  DateTime? _lastTypingSent;

  Map<String, dynamic>? _replyingTo;
  String? _editingMsgId;

  final List<String> _emojiBank = [
    '❤️', '😂', '😮', '😢', '🙏', '👍', '👎', '🔥', '🎉', '💯', 
    '✨', '😍', '👀', '🤔', '💀', '🤡', '😡', '✅', '🚀', '🌟'
  ];

  @override
  void initState() {
    super.initState();
    _cleanUpLeakedReceipts();
    connectWebSocket();
  }

  void _cleanUpLeakedReceipts() {
    for (var key in _chatBox.keys) {
      List<String> history = _chatBox.get(key, defaultValue: <dynamic>[]).cast<String>();
      bool changed = false;
      history.removeWhere((msg) {
        if (msg.contains('"type":"receipt"') || msg.contains('"type":"typing"')) { changed = true; return true; }
        return false;
      });
      if (changed) _chatBox.put(key, history);
    }
  }

  Future<bool> _confirmAction(String title, String content, String confirmText, Color confirmColor) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        title: Text(title, style: TextStyle(fontWeight: FontWeight.w800, color: confirmColor)),
        content: Text(content, style: const TextStyle(fontSize: 14, color: Colors.white70, height: 1.4)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text("Cancel", style: TextStyle(color: Colors.white54))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: confirmColor, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(confirmText, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
          )
        ],
      )
    );
    return result ?? false;
  }

  List<String> _getQuickReactions() {
    return _settingsBox.get('quick_reactions', defaultValue: <String>['❤️', '😂', '😮', '😢', '🙏']).cast<String>();
  }

  Widget _buildAvatar(String wingId, String fallbackName, {double radius = 26}) {
    final base64Str = _avatarsBox.get(wingId);
    if (base64Str != null && base64Str.isNotEmpty) {
      try { return CircleAvatar(radius: radius, backgroundImage: MemoryImage(base64Decode(base64Str)), backgroundColor: const Color(0xFF1E1E1E)); } catch (e) {}
    }
    final gradients = [
      const [Color(0xFF4facfe), Color(0xFF00f2fe)], const [Color(0xFFff0844), Color(0xFFffb199)], 
      const [Color(0xFF667eea), Color(0xFF764ba2)], const [Color(0xFF0ba360), Color(0xFF3cba92)], const [Color(0xFFf77062), Color(0xFFfe5196)], 
    ];
    final gradient = gradients[fallbackName.hashCode % gradients.length];
    String initials = fallbackName.isNotEmpty ? fallbackName.trim().split(' ').map((e) => e.isNotEmpty ? e[0] : "").take(2).join().toUpperCase() : "?";
    
    return Container(
      width: radius * 2, height: radius * 2,
      decoration: BoxDecoration(shape: BoxShape.circle, gradient: LinearGradient(colors: gradient, begin: Alignment.topLeft, end: Alignment.bottomRight)),
      alignment: Alignment.center,
      child: Text(initials, style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: radius * 0.85, letterSpacing: 0.5)),
    );
  }

  void _showNotification(String senderId, String senderName, String messageText) {
    if (activeContactId == senderId) return;
    showOverlayNotification((context) {
      return SafeArea(
        child: Container(
          margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Material(
            color: const Color(0xFF1E1E1E), elevation: 10, borderRadius: BorderRadius.circular(16),
            child: ListTile(
              leading: _buildAvatar(senderId, senderName, radius: 20),
              title: Text(senderName, style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.blueAccent)),
              subtitle: Text(messageText, maxLines: 1, overflow: TextOverflow.ellipsis),
              onTap: () { OverlaySupportEntry.of(context)?.dismiss(); setState(() { activeContactId = senderId; activeContactName = senderName; }); _scrollToBottom(); },
            ),
          ),
        ),
      );
    }, duration: const Duration(seconds: 4));
  }

  Future<void> _pickAndUploadAvatar() async {
    try {
      final XFile? image = await _picker.pickImage(source: ImageSource.gallery, maxWidth: 256, maxHeight: 256, imageQuality: 50);
      if (image == null) return;
      final bytes = await image.readAsBytes();
      final base64Str = base64Encode(bytes);
      setState(() { _avatarsBox.put(widget.myWingId, base64Str); });
      await http.post(Uri.parse("http://192.168.1.49:8080/upload-avatar"), headers: {"Content-Type": "application/json"}, body: jsonEncode({"wing_id": widget.myWingId, "avatar": base64Str}));
    } catch (e) {}
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) { Future.delayed(const Duration(milliseconds: 100), () { _scrollController.animateTo(_scrollController.position.maxScrollExtent, duration: const Duration(milliseconds: 300), curve: Curves.easeOut); }); }
  }

  void connectWebSocket() {
    channel = WebSocketChannel.connect(Uri.parse("ws://192.168.1.49:8080/ws?wing_id=${widget.myWingId}&token=debug"));

    channel.stream.listen((message) async {
      final decoded = jsonDecode(message);
      final senderId = decoded["from"];
      if (_blockedBox.containsKey(senderId)) return; 

      try {
        final senderPublicKey = await getPublicKey(senderId);
        final sharedSecret = await x25519.sharedSecretKey(keyPair: widget.myKeyPair, remotePublicKey: senderPublicKey);

        final encryptedBytes = base64Decode(decoded["message"]);
        final nonce = encryptedBytes.sublist(0, 12);
        final cipherText = encryptedBytes.sublist(12, encryptedBytes.length - 16);
        final macBytes = encryptedBytes.sublist(encryptedBytes.length - 16);
        final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes));
        final decrypted = await aes.decrypt(secretBox, secretKey: sharedSecret);

        final rawDecryptedText = utf8.decode(decrypted);

        Map<String, dynamic>? incomingData;
        bool isProtocolMessage = false;

        try { incomingData = jsonDecode(rawDecryptedText); isProtocolMessage = incomingData != null && incomingData.containsKey('type'); } catch (_) {}

        if (isProtocolMessage) {
          if (incomingData!['type'] == 'typing') {
            if (activeContactId == senderId) { setState(() => _isFriendTyping = true); _typingTimer?.cancel(); _typingTimer = Timer(const Duration(seconds: 2), () { if (mounted) setState(() => _isFriendTyping = false); }); }
          } 
          else if (incomingData['type'] == 'receipt') {
            try {
              List<String> history = _chatBox.get(senderId, defaultValue: <dynamic>[]).cast<String>();
              bool updated = false;
              for (int i = 0; i < history.length; i++) {
                final m = jsonDecode(history[i]);
                if (m['id'] == incomingData['id']) {
                  if (incomingData['status'] == 'read') m['status'] = 3; 
                  else if (incomingData['status'] == 'delivered' && (m['status'] == null || m['status'] < 3)) m['status'] = 2; 
                  history[i] = jsonEncode(m); updated = true; break;
                }
              }
              if (updated) { await _chatBox.put(senderId, history); if (mounted) setState(() {}); }
            } catch (e) {}
          } 
          else if (incomingData['type'] == 'edit') {
            List<String> history = _chatBox.get(senderId, defaultValue: <dynamic>[]).cast<String>();
            bool updated = false;
            for (int i = 0; i < history.length; i++) {
              final m = jsonDecode(history[i]);
              if (m['id'] == incomingData['id']) { m['text'] = incomingData['text']; m['isEdited'] = true; history[i] = jsonEncode(m); updated = true; break; }
            }
            if (updated) { await _chatBox.put(senderId, history); if (mounted) setState(() {}); }
          }
          else if (incomingData['type'] == 'delete') {
            List<String> history = _chatBox.get(senderId, defaultValue: <dynamic>[]).cast<String>();
            int? toRemove;
            for (int i = 0; i < history.length; i++) { if (jsonDecode(history[i])['id'] == incomingData['id']) { toRemove = i; break; } }
            if (toRemove != null) { history.removeAt(toRemove); await _chatBox.put(senderId, history); if (mounted) setState(() {}); }
          }
          else if (incomingData['type'] == 'react') {
            List<String> history = _chatBox.get(senderId, defaultValue: <dynamic>[]).cast<String>();
            bool updated = false;
            for (int i = 0; i < history.length; i++) {
              final m = jsonDecode(history[i]);
              if (m['id'] == incomingData['id']) {
                m['reactions'] = m['reactions'] ?? {};
                if (incomingData['emoji'] == "") { m['reactions'].remove(senderId); } else { m['reactions'][senderId] = incomingData['emoji']; }
                history[i] = jsonEncode(m); updated = true; break;
              }
            }
            if (updated) { await _chatBox.put(senderId, history); if (mounted) setState(() {}); }
          }
          else if (incomingData['type'] == 'chat') {
            final displayName = _contactsBox.get(senderId, defaultValue: senderId);
            bool isReadNow = (activeContactId == senderId);
            if (activeContactId == senderId) { setState(() => _isFriendTyping = false); _typingTimer?.cancel(); }

            final msgObj = {
              "id": incomingData['id'], "sender": displayName, "text": incomingData['text'], "time": DateTime.now().millisecondsSinceEpoch,
              "isReadLocally": isReadNow, "replyTo": incomingData['replyTo'] 
            };

            List<String> history = _chatBox.get(senderId, defaultValue: <dynamic>[]).cast<String>();
            history.add(jsonEncode(msgObj));
            await _chatBox.put(senderId, history);
            if (mounted) setState(() {}); 
            if (isReadNow) { _scrollToBottom(); sendActionMessage(senderId, "receipt", messageId: incomingData['id'], status: "read"); } 
            else { sendActionMessage(senderId, "receipt", messageId: incomingData['id'], status: "delivered"); _showNotification(senderId, displayName, incomingData['text']); }
          }
        } else {
          if (!rawDecryptedText.contains('"type":"receipt"') && !rawDecryptedText.contains('"type":"typing"')) {
            final displayName = _contactsBox.get(senderId, defaultValue: senderId);
            final msgObj = {"sender": displayName, "text": rawDecryptedText, "time": DateTime.now().millisecondsSinceEpoch};
            List<String> history = _chatBox.get(senderId, defaultValue: <dynamic>[]).cast<String>();
            history.add(jsonEncode(msgObj)); await _chatBox.put(senderId, history); if (mounted) setState(() {}); 
          }
        }
      } catch (e) { print("DECRYPT ERROR: $e"); }
    });
  }

  Future<void> sendActionMessage(String receiverId, String type, {String? messageId, String? status, String? text, String? emoji, Map<String, dynamic>? replyTo}) async {
    try {
      final receiverPublicKey = await getPublicKey(receiverId);
      final sharedSecret = await x25519.sharedSecretKey(keyPair: widget.myKeyPair, remotePublicKey: receiverPublicKey);

      Map<String, dynamic> payload = {"type": type};
      if (messageId != null) payload["id"] = messageId;
      if (status != null) payload["status"] = status;
      if (text != null) payload["text"] = text;
      if (emoji != null) payload["emoji"] = emoji;
      if (replyTo != null) payload["replyTo"] = replyTo;
      
      final nonce = aes.newNonce();
      final secretBox = await aes.encrypt(utf8.encode(jsonEncode(payload)), secretKey: sharedSecret, nonce: nonce);
      final combined = [...nonce, ...secretBox.cipherText, ...secretBox.mac.bytes];
      channel.sink.add(jsonEncode({"from": widget.myWingId, "to": receiverId, "message": base64Encode(combined)}));
    } catch (e) {}
  }

  void _onMessageTextChanged(String text) {
    if (activeContactId == null) return;
    final now = DateTime.now();
    if (_lastTypingSent == null || now.difference(_lastTypingSent!) > const Duration(seconds: 2)) {
      _lastTypingSent = now;
      sendActionMessage(activeContactId!, "typing");
    }
  }

  Future<SimplePublicKey> getPublicKey(String wingId) async {
    final res = await http.get(Uri.parse("http://192.168.1.49:8080/public-key/$wingId"));
    final data = jsonDecode(res.body);
    if (data["username"] != null && !_contactsBox.containsKey(wingId)) { await _contactsBox.put(wingId, data["username"]); }
    if (data["avatar"] != null && data["avatar"].toString().isNotEmpty) { await _avatarsBox.put(wingId, data["avatar"]); }
    if (mounted) setState(() {}); 
    return SimplePublicKey(base64Decode(data["public_key"]), type: KeyPairType.x25519);
  }

  Future<void> sendMessage() async {
    if (activeContactId == null || _msgController.text.trim().isEmpty) return;
    final messageText = _msgController.text.trim();
    _msgController.clear(); 

    if (_editingMsgId != null) {
      final msgIdToEdit = _editingMsgId!;
      setState(() => _editingMsgId = null); 
      List<String> history = _chatBox.get(activeContactId, defaultValue: <dynamic>[]).cast<String>();
      bool updated = false;
      for (int i = 0; i < history.length; i++) {
        final m = jsonDecode(history[i]);
        if (m['id'] == msgIdToEdit) { m['text'] = messageText; m['isEdited'] = true; history[i] = jsonEncode(m); updated = true; break; }
      }
      if (updated) { await _chatBox.put(activeContactId, history); sendActionMessage(activeContactId!, "edit", messageId: msgIdToEdit, text: messageText); if (mounted) setState(() {}); }
      return;
    }

    final msgId = uuid.v4();
    final replyContext = _replyingTo;
    setState(() => _replyingTo = null); 

    final msgObj = { "id": msgId, "sender": "Me", "text": messageText, "time": DateTime.now().millisecondsSinceEpoch, "status": 1, if (replyContext != null) "replyTo": replyContext };
    List<String> history = _chatBox.get(activeContactId, defaultValue: <dynamic>[]).cast<String>();
    history.add(jsonEncode(msgObj));
    await _chatBox.put(activeContactId, history);
    if (mounted) setState(() {}); 
    _scrollToBottom();
    sendActionMessage(activeContactId!, "chat", messageId: msgId, text: messageText, replyTo: replyContext);
  }

  Future<void> _toggleReaction(String msgId, String emoji) async {
    if (activeContactId == null) return;
    List<String> history = _chatBox.get(activeContactId, defaultValue: <dynamic>[]).cast<String>();
    bool updated = false;
    String reactionToSend = emoji;

    for (int i = 0; i < history.length; i++) {
      final m = jsonDecode(history[i]);
      if (m['id'] == msgId) {
        m['reactions'] = m['reactions'] ?? {};
        if (m['reactions']['Me'] == emoji) { m['reactions'].remove('Me'); reactionToSend = ""; } else { m['reactions']['Me'] = emoji; }
        history[i] = jsonEncode(m); updated = true; break;
      }
    }
    if (updated) { await _chatBox.put(activeContactId, history); setState(() {}); sendActionMessage(activeContactId!, "react", messageId: msgId, emoji: reactionToSend); }
  }

  Future<void> _setCustomEmoji(int slotIndex, List<String> currentReactions, StateSetter setModalState) async {
    TextEditingController emojiCtrl = TextEditingController();
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        title: const Text("Enter an Emoji", style: TextStyle(fontWeight: FontWeight.bold)),
        content: TextField(
          controller: emojiCtrl, autofocus: true, style: const TextStyle(fontSize: 32), textAlign: TextAlign.center,
          decoration: const InputDecoration(hintText: "😃", border: InputBorder.none),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel", style: TextStyle(color: Colors.white54))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            onPressed: () {
              String newEmoji = emojiCtrl.text.trim();
              if (newEmoji.isNotEmpty) {
                if (currentReactions.contains(newEmoji) && currentReactions.indexOf(newEmoji) != slotIndex) {
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Emoji already in use! Choose a unique one.")));
                } else {
                  setModalState(() => currentReactions[slotIndex] = newEmoji);
                  _settingsBox.put('quick_reactions', currentReactions);
                  setState(() {}); 
                  Navigator.pop(ctx);
                }
              }
            },
            child: const Text("Save", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
          )
        ],
      )
    );
  }

  void _showCustomizeReactionsDialog() {
    List<String> currentReactions = _getQuickReactions();

    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF141414),
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            return SafeArea(
              child: Container(
                height: MediaQuery.of(context).size.height * 0.55,
                padding: const EdgeInsets.symmetric(vertical: 20),
                child: Column(
                  children: [
                    const Text("Customize Quick Reactions", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
                    const SizedBox(height: 8),
                    const Text("Tap any slot to pick a custom emoji from your keyboard.", style: TextStyle(color: Colors.white54, fontSize: 12)),
                    const SizedBox(height: 20),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                      children: List.generate(5, (index) {
                        return GestureDetector(
                          onTap: () => _setCustomEmoji(index, currentReactions, setModalState),
                          child: Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(color: const Color(0xFF1E1E1E), border: Border.all(color: Colors.white10), borderRadius: BorderRadius.circular(16)),
                            child: Text(currentReactions[index], style: const TextStyle(fontSize: 28)),
                          ),
                        );
                      }),
                    ),
                    const SizedBox(height: 20),
                    const Divider(color: Colors.white10),
                    Expanded(
                      child: GridView.builder(
                        padding: const EdgeInsets.all(16),
                        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(crossAxisCount: 6, crossAxisSpacing: 10, mainAxisSpacing: 10),
                        itemCount: _emojiBank.length,
                        itemBuilder: (context, index) {
                          final emoji = _emojiBank[index];
                          return GestureDetector(
                            onTap: () async {
                              setModalState(() {
                                currentReactions[selectedSlot] = emoji;
                                if (selectedSlot < 4) selectedSlot++; 
                              });
                              await _settingsBox.put('quick_reactions', currentReactions);
                              setState(() {}); 
                            },
                            child: Container(
                              alignment: Alignment.center,
                              decoration: BoxDecoration(color: const Color(0xFF1E1E1E), borderRadius: BorderRadius.circular(12)),
                              child: Text(emoji, style: const TextStyle(fontSize: 24)),
                            ),
                          );
                        },
                      ),
                    )
                  ],
                ),
              ),
            );
          }
        );
      }
    );
  }

  void _showMessageOptions(String msgId, Map<String, dynamic> msgData, bool isMe) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF141414),
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (context) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    ..._getQuickReactions().map((emoji) {
                      return GestureDetector(onTap: () { Navigator.pop(context); _toggleReaction(msgId, emoji); }, child: Text(emoji, style: const TextStyle(fontSize: 32)));
                    }).toList(),
                    GestureDetector(
                      onTap: () { Navigator.pop(context); _showCustomizeReactionsDialog(); },
                      child: Container(padding: const EdgeInsets.all(8), decoration: BoxDecoration(color: const Color(0xFF1E1E1E), shape: BoxShape.circle, border: Border.all(color: Colors.white10)), child: const Icon(Icons.add, color: Colors.white70)),
                    )
                  ],
                ),
                const SizedBox(height: 16), const Divider(color: Colors.white10),
                ListTile(leading: const Icon(Icons.reply, color: Colors.white), title: const Text('Reply'), onTap: () { Navigator.pop(context); setState(() { _replyingTo = {"id": msgId, "sender": msgData['sender'], "text": msgData['text']}; }); }),
                ListTile(leading: const Icon(Icons.copy, color: Colors.white), title: const Text('Copy'), onTap: () { Clipboard.setData(ClipboardData(text: msgData['text'])); Navigator.pop(context); ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Copied to clipboard."))); }),
                if (isMe) ListTile(leading: const Icon(Icons.edit, color: Colors.white), title: const Text('Edit'), onTap: () { Navigator.pop(context); setState(() { _editingMsgId = msgId; _msgController.text = msgData['text']; }); }),
                if (isMe) ListTile(leading: const Icon(Icons.delete_outline, color: Colors.redAccent), title: const Text('Unsend', style: TextStyle(color: Colors.redAccent)), onTap: () async { Navigator.pop(context); if (await _confirmAction("Unsend Message?", "This will permanently remove the message for everyone in the chat.", "Unsend", Colors.redAccent)) { List<String> history = _chatBox.get(activeContactId, defaultValue: <dynamic>[]).cast<String>(); int? toRemove; for (int i = 0; i < history.length; i++) { if (jsonDecode(history[i])['id'] == msgId) { toRemove = i; break; } } if (toRemove != null) { history.removeAt(toRemove); await _chatBox.put(activeContactId, history); setState(() {}); sendActionMessage(activeContactId!, "delete", messageId: msgId); } } }),
              ],
            ),
          ),
        );
      }
    );
  }

  void _showChangePasswordDialog() {
    final oldPassCtrl = TextEditingController();
    final newPassCtrl = TextEditingController();
    
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        title: const Text("Change Password", style: TextStyle(fontWeight: FontWeight.w800)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(controller: oldPassCtrl, obscureText: true, decoration: const InputDecoration(labelText: "Current Password")),
            const SizedBox(height: 12),
            TextField(controller: newPassCtrl, obscureText: true, decoration: const InputDecoration(labelText: "New Password")),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("Cancel", style: TextStyle(color: Colors.white54))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            onPressed: () async {
              if (oldPassCtrl.text.isEmpty || newPassCtrl.text.isEmpty) return;
              try {
                final res = await http.post(
                  Uri.parse("http://192.168.1.49:8080/change-password"),
                  headers: {"Content-Type": "application/json"},
                  body: jsonEncode({"wing_id": widget.myWingId, "old_password": oldPassCtrl.text, "new_password": newPassCtrl.text})
                );
                if (res.statusCode == 200) {
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Password updated successfully.")));
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Failed to update password. Check current password.", style: TextStyle(color: Colors.white)), backgroundColor: Colors.redAccent));
                }
              } catch (e) { ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Network error."))); }
            },
            child: const Text("Update", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
          )
        ]
      )
    );
  }

  void _showAccountSettings() {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF141414),
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (context) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text("Account Settings", style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Colors.white)),
                const SizedBox(height: 8),
                const Text("Manage your session and local data.", style: TextStyle(color: Colors.white54)),
                const SizedBox(height: 24),
                
                ListTile(
                  leading: const Icon(Icons.lock_reset, color: Colors.white),
                  title: const Text("Change Password"),
                  subtitle: const Text("Update your login password securely.", style: TextStyle(fontSize: 12, color: Colors.white54)),
                  onTap: () { Navigator.pop(context); _showChangePasswordDialog(); },
                ),
                const Divider(color: Colors.white10),

                ListTile(
                  leading: const Icon(Icons.logout, color: Colors.white),
                  title: const Text("Logout"),
                  subtitle: const Text("Logs you out, requiring password to re-enter.", style: TextStyle(fontSize: 12, color: Colors.white54)),
                  onTap: () async {
                    if (await _confirmAction("Logout?", "Are you sure you want to log out? You will need your password to re-enter.", "Logout", Colors.blueAccent)) {
                      if (!mounted) return;
                      Navigator.pop(context);
                      await storage.write(key: "is_logged_in", value: "false"); 
                      if (mounted) Navigator.pushReplacement(context, MaterialPageRoute(builder: (context) => const AuthScreen()));
                    }
                  },
                ),
                const Divider(color: Colors.white10),
                
                ListTile(
                  leading: const Icon(Icons.cleaning_services, color: Colors.orangeAccent),
                  title: const Text("Wipe Local Data", style: TextStyle(color: Colors.orangeAccent)),
                  subtitle: const Text("Deletes messages from this device. Account remains.", style: TextStyle(fontSize: 12, color: Colors.white54)),
                  onTap: () async {
                    if (await _confirmAction("Wipe Local Data?", "This will permanently delete all messages and contacts from this device. Your account will remain on the server.", "Wipe Data", Colors.orangeAccent)) {
                      if (!mounted) return;
                      Navigator.pop(context);
                      await storage.deleteAll(); 
                      await _chatBox.clear(); await _contactsBox.clear(); await _blockedBox.clear(); await _avatarsBox.clear(); 
                      if (mounted) Navigator.pushReplacement(context, MaterialPageRoute(builder: (context) => const AuthScreen()));
                    }
                  },
                ),
                const Divider(color: Colors.white10),

                ListTile(
                  leading: const Icon(Icons.delete_forever, color: Colors.redAccent),
                  title: const Text("Delete Account", style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
                  subtitle: const Text("Permanently destroys account on server and wipes device.", style: TextStyle(fontSize: 12, color: Colors.white54)),
                  onTap: () async {
                    if (await _confirmAction("Delete Account?", "This action is completely irreversible. Your account, contacts, and messages will be permanently destroyed.", "Delete Forever", Colors.redAccent)) {
                      if (!mounted) return;
                      Navigator.pop(context);
                      try {
                        await http.post(
                          Uri.parse("http://192.168.1.49:8080/delete-account"),
                          headers: {"Content-Type": "application/json"},
                          body: jsonEncode({"wing_id": widget.myWingId}),
                        );
                      } catch (e) { print("Could not reach server."); }
                      await storage.deleteAll(); 
                      await _chatBox.clear(); await _contactsBox.clear(); await _blockedBox.clear(); await _avatarsBox.clear(); 
                      if (mounted) Navigator.pushReplacement(context, MaterialPageRoute(builder: (context) => const AuthScreen()));
                    }
                  },
                ),
              ],
            ),
          ),
        );
      }
    );
  }

  void _handleChatMenuAction(String action) async {
    if (activeContactId == null) return;
    final targetId = activeContactId!;
    final targetName = activeContactName ?? targetId;

    if (action == 'clear') {
      if (await _confirmAction("Clear Chat?", "Are you sure you want to clear all messages with $targetName? This cannot be undone.", "Clear", Colors.orangeAccent)) {
        await _chatBox.delete(targetId);
        setState(() {});
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Chat cleared.")));
      }
    } 
    else if (action == 'delete') {
      if (await _confirmAction("Delete Contact?", "Are you sure you want to delete $targetName from your contacts? The chat history will also be removed.", "Delete", Colors.redAccent)) {
        await _chatBox.delete(targetId);
        await _contactsBox.delete(targetId);
        setState(() => activeContactId = null); 
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Contact deleted.")));
      }
    } 
    else if (action == 'block') {
      if (await _confirmAction("Block User?", "Are you sure you want to block $targetName? You will no longer receive their messages and the chat will be deleted.", "Block", Colors.redAccent)) {
        await _blockedBox.put(targetId, targetName); 
        await _chatBox.delete(targetId);       
        await _contactsBox.delete(targetId);   
        setState(() => activeContactId = null); 
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("User blocked."), backgroundColor: Colors.redAccent));
      }
    }
  }

  void showAddContactDialog() {
    final idController = TextEditingController(); final nameController = TextEditingController();
    showDialog(context: context, builder: (context) => AlertDialog(backgroundColor: const Color(0xFF1E1E1E), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)), title: const Text("Add New Contact", style: TextStyle(fontWeight: FontWeight.w800)), content: Column(mainAxisSize: MainAxisSize.min, children: [TextField(controller: idController, decoration: const InputDecoration(labelText: "Friend's Wing ID")), const SizedBox(height: 12), TextField(controller: nameController, decoration: const InputDecoration(labelText: "Saved Name"))]), actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text("Cancel", style: TextStyle(color: Colors.white54))), ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))), onPressed: () { if (idController.text.isNotEmpty && nameController.text.isNotEmpty) { _contactsBox.put(idController.text.trim(), nameController.text.trim()); getPublicKey(idController.text.trim()); if (mounted) setState(() {}); Navigator.pop(context); } }, child: const Text("Save", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)))],));
  }

  void showBlockedUsersDialog() {
    showDialog(context: context, builder: (context) => StatefulBuilder(builder: (context, setStateDialog) { final blockedList = _blockedBox.keys.toList(); return AlertDialog(backgroundColor: const Color(0xFF1E1E1E), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)), title: const Text("Blocked Users", style: TextStyle(fontWeight: FontWeight.w800)), contentPadding: const EdgeInsets.only(top: 20, bottom: 10), content: SizedBox(width: double.maxFinite, child: blockedList.isEmpty ? const Padding(padding: EdgeInsets.all(20.0), child: Text("You have no blocked users.", textAlign: TextAlign.center, style: TextStyle(color: Colors.white54))) : ListView.builder(shrinkWrap: true, itemCount: blockedList.length, itemBuilder: (ctx, i) { final blockedId = blockedList[i] as String; final displayName = _blockedBox.get(blockedId) is String ? _blockedBox.get(blockedId) : "Unknown"; return ListTile(contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 4), leading: _buildAvatar(blockedId, displayName, radius: 18), title: Text(displayName, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15)), subtitle: Text(blockedId, style: const TextStyle(fontSize: 10, color: Colors.white38)), trailing: OutlinedButton(style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.blueAccent), padding: const EdgeInsets.symmetric(horizontal: 12), minimumSize: const Size(0, 32)), child: const Text("Unblock", style: TextStyle(color: Colors.blueAccent, fontSize: 12, fontWeight: FontWeight.bold)), onPressed: () { _blockedBox.delete(blockedId); setStateDialog(() {}); if (mounted) setState(() {}); })); })), actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text("Close", style: TextStyle(color: Colors.white54)))]); }));
  }

  void copyMyId() { Clipboard.setData(ClipboardData(text: widget.myWingId)); ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Wing ID copied!"), backgroundColor: Colors.green, duration: Duration(seconds: 2))); }
  String _formatDateHeader(DateTime date) { final now = DateTime.now(); if (date.year == now.year && date.month == now.month && date.day == now.day) return "Today"; final yesterday = now.subtract(const Duration(days: 1)); if (date.year == yesterday.year && date.month == yesterday.month && date.day == yesterday.day) return "Yesterday"; return DateFormat('MMM d, yyyy').format(date); }

  Widget _buildDashboardView() {
    final allContacts = _contactsBox.keys.toList();
    
    return Scaffold(
      key: const ValueKey('dash_view'),
      appBar: AppBar(
        backgroundColor: const Color(0xFF141414), 
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1.0),
          child: Container(color: Colors.white.withOpacity(0.05), height: 1.0),
        ),
        title: Row(
          mainAxisSize: MainAxisSize.min, 
          crossAxisAlignment: CrossAxisAlignment.center, 
          children: [
            Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                const Text("Connect", style: TextStyle(fontWeight: FontWeight.w800, fontSize: 20, letterSpacing: -0.5, height: 1.1, color: Colors.white)),
                Text("BY WINGS", style: TextStyle(fontSize: 9, color: Colors.blueAccent, letterSpacing: 1.5, fontWeight: FontWeight.w800)),
              ],
            )
          ],
        ),
      ),
      drawer: Drawer(
        backgroundColor: const Color(0xFF121212),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.only(top: 60, left: 24, bottom: 24, right: 24),
              decoration: BoxDecoration(
                color: const Color(0xFF1A1A1A),
                border: Border(bottom: BorderSide(color: Colors.white.withOpacity(0.05))),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  GestureDetector(
                    onTap: _pickAndUploadAvatar,
                    child: Stack(
                      children: [
                        _buildAvatar(widget.myWingId, "Me", radius: 36),
                        Positioned(
                          bottom: 0,
                          right: 0,
                          child: Container(
                            padding: const EdgeInsets.all(4),
                            decoration: const BoxDecoration(color: Colors.blueAccent, shape: BoxShape.circle),
                            child: const Icon(Icons.camera_alt, size: 14, color: Colors.white),
                          ),
                        )
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Text("My Account", style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800, letterSpacing: -0.3, color: Colors.white)),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Text(widget.myWingId, style: const TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.w500)),
                      const SizedBox(width: 8),
                      InkWell(onTap: copyMyId, child: const Icon(Icons.copy, size: 14, color: Colors.white54)),
                    ],
                  )
                ],
              ),
            ),
            const SizedBox(height: 12),
            ListTile(
              leading: const Icon(Icons.person_add_alt_1, color: Colors.white),
              title: const Text("New Contact", style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
              onTap: () { Navigator.pop(context); showAddContactDialog(); },
            ),
            ListTile(
              leading: const Icon(Icons.block, color: Colors.white),
              title: const Text("Blocked Users", style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
              onTap: () { Navigator.pop(context); showBlockedUsersDialog(); },
            ),
            const Spacer(),
            Divider(color: Colors.white.withOpacity(0.05)),
            ListTile(
              leading: const Icon(Icons.settings, color: Colors.white70),
              title: const Text("Account Settings", style: TextStyle(fontWeight: FontWeight.w700, color: Colors.white70)),
              onTap: () { Navigator.pop(context); _showAccountSettings(); },
            ),
            const SizedBox(height: 12),
          ],
        ),
      ),
      floatingActionButton: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(18),
          boxShadow: [
            BoxShadow(
              color: Colors.blueAccent.withOpacity(0.4),
              blurRadius: 16,
              offset: const Offset(0, 8),
            )
          ]
        ),
        child: FloatingActionButton(
          onPressed: showAddContactDialog,
          backgroundColor: Colors.blueAccent,
          elevation: 0, 
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
          child: const Icon(Icons.edit_square, color: Colors.white, size: 22), 
        ),
      ),
      body: allContacts.isEmpty 
        ? const Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.chat_bubble_outline, size: 60, color: Colors.white24),
                SizedBox(height: 16),
                Text("No messages yet.\nTap the button below to start a secure chat.", 
                  textAlign: TextAlign.center, style: TextStyle(color: Colors.white54, fontSize: 15)),
              ],
            ),
          )
        : ListView.builder(
            itemCount: allContacts.length,
            itemBuilder: (context, index) {
              final contactId = allContacts[index] as String;
              final savedName = _contactsBox.get(contactId, defaultValue: contactId) as String;
              List<String> history = _chatBox.get(contactId, defaultValue: <dynamic>[]).cast<String>();
              
              String lastMsg = "Tap to start chatting!";
              String timeStr = "";
              int status = 0;
              bool isMe = false;
              
              if (history.isNotEmpty) {
                try {
                  final data = jsonDecode(history.last);
                  lastMsg = data['text'] ?? "Image/File";
                  status = data['status'] ?? 0;
                  isMe = data['sender'] == 'Me';
                  if (data['time'] != null) {
                     timeStr = DateFormat('h:mm a').format(DateTime.fromMillisecondsSinceEpoch(data['time']));
                  }
                } catch (e) {
                  lastMsg = "Encrypted message";
                }
              }

              return InkWell(
                onTap: () async {
                  setState(() {
                    activeContactId = contactId;
                    activeContactName = savedName;
                  });
                  _scrollToBottom();
                  
                  bool updated = false;
                  for (int i = 0; i < history.length; i++) {
                    try {
                      final m = jsonDecode(history[i]);
                      if (m['sender'] != 'Me' && m['isReadLocally'] != true) {
                        m['isReadLocally'] = true; 
                        history[i] = jsonEncode(m);
                        updated = true;
                        sendActionMessage(contactId, "receipt", messageId: m['id'], status: "read"); 
                      }
                    } catch (_) {}
                  }
                  if (updated) await _chatBox.put(contactId, history);
                },
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                  child: Row(
                    children: [
                      _buildAvatar(contactId, savedName, radius: 28), 
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(savedName, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 17, letterSpacing: -0.2, color: Colors.white)),
                                Text(timeStr, style: const TextStyle(fontSize: 12, color: Colors.white54, fontWeight: FontWeight.w500)),
                              ],
                            ),
                            const SizedBox(height: 6),
                            Row(
                              crossAxisAlignment: CrossAxisAlignment.center,
                              children: [
                                if (isMe && history.isNotEmpty) ...[
                                  Icon(status >= 2 ? Icons.done_all : Icons.check, size: 15, color: status == 3 ? Colors.blueAccent : Colors.white38),
                                  const SizedBox(width: 6),
                                ],
                                Expanded(child: Text(lastMsg, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white60, fontSize: 14, fontWeight: FontWeight.w400))),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
    );
  }

  Widget _buildChatView() {
    List<String> activeMessages = _chatBox.get(activeContactId, defaultValue: <dynamic>[]).cast<String>();

    return Scaffold(
      key: const ValueKey('chat_view'),
      appBar: AppBar(
        backgroundColor: const Color(0xFF141414), 
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1.0),
          child: Container(color: Colors.white.withOpacity(0.05), height: 1.0),
        ),
        leadingWidth: 48, 
        leading: IconButton(
          padding: const EdgeInsets.only(left: 8),
          icon: const Icon(Icons.arrow_back_ios_new, size: 20), 
          onPressed: () => setState(() { activeContactId = null; _replyingTo = null; _editingMsgId = null; })
        ),
        title: Row(
          mainAxisSize: MainAxisSize.min, 
          crossAxisAlignment: CrossAxisAlignment.center, 
          children: [
            _buildAvatar(activeContactId!, activeContactName!, radius: 18),
            const SizedBox(width: 12),
            Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(activeContactName!, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 18, letterSpacing: -0.3, height: 1.2)),
                if (_isFriendTyping)
                   const Text("typing...", style: TextStyle(fontSize: 12, color: Colors.blueAccent, fontStyle: FontStyle.italic, fontWeight: FontWeight.w600, height: 1.2)),
              ],
            ),
          ],
        ),
        actions: [
          PopupMenuButton<String>(
            color: const Color(0xFF1E1E1E),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            icon: const Icon(Icons.more_vert, size: 22),
            onSelected: _handleChatMenuAction,
            itemBuilder: (context) => [
              const PopupMenuItem(value: 'clear', child: Text('Clear Chat', style: TextStyle(fontWeight: FontWeight.w500))),
              const PopupMenuItem(value: 'delete', child: Text('Delete Contact', style: TextStyle(fontWeight: FontWeight.w500))),
              const PopupMenuItem(value: 'block', child: Text('Block User', style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.w600))),
            ],
          )
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scrollController, 
              itemCount: activeMessages.length,
              itemBuilder: (context, index) {
                final prev = index > 0 ? activeMessages[index - 1] : null;
                final next = index < activeMessages.length - 1 ? activeMessages[index + 1] : null;
                return _buildMessageBubble(activeMessages[index], prev, next);
              },
            ),
          ),
          
          if (_replyingTo != null || _editingMsgId != null)
            Container(
              margin: const EdgeInsets.symmetric(horizontal: 16),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: const Color(0xFF1A1A1A), borderRadius: const BorderRadius.vertical(top: Radius.circular(16)), border: Border.all(color: Colors.white10)),
              child: Row(
                children: [
                  Icon(_editingMsgId != null ? Icons.edit : Icons.reply, color: Colors.blueAccent, size: 20),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(_editingMsgId != null ? "Editing Message" : "Replying to ${_replyingTo!['sender']}", style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: Colors.blueAccent)),
                        Text(_editingMsgId != null ? "Change your text below" : _replyingTo!['text'], maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white54, fontSize: 13)),
                      ],
                    ),
                  ),
                  IconButton(icon: const Icon(Icons.close, size: 18, color: Colors.white54), onPressed: () => setState(() { _replyingTo = null; _editingMsgId = null; _msgController.clear(); }))
                ],
              ),
            ),

          Padding(
            padding: const EdgeInsets.only(left: 12, right: 12, bottom: 12, top: 4),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Expanded(
                  child: Container(
                    decoration: BoxDecoration(
                      color: const Color(0xFF1A1A1A), 
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(color: Colors.white.withOpacity(0.05))
                    ),
                    child: TextField(
                      controller: _msgController,
                      onChanged: _onMessageTextChanged, 
                      minLines: 1,
                      maxLines: 5, 
                      style: const TextStyle(fontSize: 15),
                      decoration: const InputDecoration(
                        hintText: "Message",
                        hintStyle: TextStyle(color: Colors.white38, fontWeight: FontWeight.w500),
                        border: InputBorder.none,
                        contentPadding: EdgeInsets.symmetric(horizontal: 20, vertical: 14)
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                CircleAvatar(
                  radius: 24, 
                  backgroundColor: Colors.blueAccent, 
                  child: IconButton(icon: Icon(_editingMsgId != null ? Icons.check : Icons.send, color: Colors.white, size: 20), onPressed: sendMessage)
                )
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _buildMessageBubble(String rawData, String? prevData, String? nextData) {
    bool isMe = false; String text = ""; DateTime? msgDate; int status = 0; 
    bool showTail = true; bool showDateDivider = false;
    String? msgId; Map<String, dynamic>? replyTo; bool isEdited = false; Map<String, dynamic>? reactions;

    Map<String, dynamic> parsedData = {};

    try {
      parsedData = jsonDecode(rawData);
      msgId = parsedData['id'];
      isMe = parsedData['sender'] == 'Me';
      text = parsedData['text'] ?? "";
      status = parsedData['status'] ?? 0;
      isEdited = parsedData['isEdited'] ?? false;
      replyTo = parsedData['replyTo'];
      reactions = parsedData['reactions'];
      if (parsedData['time'] != null) msgDate = DateTime.fromMillisecondsSinceEpoch(parsedData['time']);
    } catch (e) { return const SizedBox(); } 

    if (msgDate != null) {
      if (prevData == null) { showDateDivider = true; } else {
        try {
          final pDate = DateTime.fromMillisecondsSinceEpoch(jsonDecode(prevData)['time']);
          if (msgDate.day != pDate.day || msgDate.month != pDate.month || msgDate.year != pDate.year) showDateDivider = true;
        } catch (_) {}
      }
      if (nextData != null) {
        try { if (jsonDecode(nextData)['sender'] == (isMe ? 'Me' : activeContactName)) showTail = false; } catch (_) {}
      }
    }

    final bubble = Stack(
      clipBehavior: Clip.none,
      children: [
        Align(
          alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
          child: GestureDetector(
            onLongPress: msgId != null ? () => _showMessageOptions(msgId!, parsedData, isMe) : null,
            onDoubleTap: msgId != null ? () => _toggleReaction(msgId!, '❤️') : null, 
            child: Container(
              margin: EdgeInsets.only(top: 2, bottom: (showTail || (reactions != null && reactions.isNotEmpty)) ? 16 : 2, left: 12, right: 12),
              padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 14),
              constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.75), 
              decoration: BoxDecoration(
                color: isMe ? Colors.blueAccent : const Color(0xFF1E1E1E), 
                border: isMe ? null : Border.all(color: Colors.white10),
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(18), topRight: const Radius.circular(18),
                  bottomLeft: Radius.circular((!isMe && showTail) ? 4 : 18), 
                  bottomRight: Radius.circular((isMe && showTail) ? 4 : 18), 
                ),
              ),
              child: Column(
                crossAxisAlignment: isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                children: [
                  if (replyTo != null)
                    Container(
                      margin: const EdgeInsets.only(bottom: 8),
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.black.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(8),
                        border: Border(left: BorderSide(color: isMe ? Colors.white : Colors.blueAccent, width: 4))
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(replyTo['sender'], style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: isMe ? Colors.white : Colors.blueAccent)),
                          const SizedBox(height: 2),
                          Text(replyTo['text'], maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 13, color: Colors.white70)),
                        ],
                      ),
                    ),
                  Text(text, style: const TextStyle(fontSize: 15, color: Colors.white, height: 1.3)),
                  const SizedBox(height: 4),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (isEdited) const Text("(edited) ", style: TextStyle(fontSize: 10, color: Colors.white54, fontStyle: FontStyle.italic)),
                      Text(msgDate != null ? DateFormat('h:mm a').format(msgDate) : "", style: TextStyle(fontSize: 10, color: isMe ? Colors.white.withOpacity(0.7) : Colors.white54, fontWeight: FontWeight.w500)),
                      if (isMe) ...[
                        const SizedBox(width: 4),
                        Icon(status >= 2 ? Icons.done_all : Icons.check, size: 14, color: status == 3 ? Colors.white : Colors.white.withOpacity(0.6)),
                      ]
                    ],
                  )
                ],
              ),
            ),
          ),
        ),
        if (reactions != null && reactions.isNotEmpty)
          Positioned(
            bottom: 4,
            right: isMe ? 24 : null,
            left: isMe ? null : 24,
            child: AnimatedSize(
              duration: const Duration(milliseconds: 300),
              curve: Curves.easeOutBack,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(color: const Color(0xFF2A2A2A), borderRadius: BorderRadius.circular(12), border: Border.all(color: const Color(0xFF0A0A0A), width: 2)),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: reactions.values.map((emoji) => Text(emoji.toString(), style: const TextStyle(fontSize: 12))).toList(),
                ),
              ),
            ),
          )
      ],
    );

    final wrappedBubble = msgId != null ? Dismissible(
      key: Key(msgId!),
      direction: DismissDirection.endToStart, 
      confirmDismiss: (direction) async {
        setState(() { _replyingTo = {"id": msgId, "sender": parsedData['sender'], "text": parsedData['text']}; });
        return false; 
      },
      background: Container(alignment: Alignment.centerRight, padding: const EdgeInsets.only(right: 20), child: const Icon(Icons.reply, color: Colors.white54)),
      child: bubble,
    ) : bubble;

    if (showDateDivider && msgDate != null) {
      return Column(
        children: [
          Container(
            margin: const EdgeInsets.symmetric(vertical: 18),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
            decoration: BoxDecoration(color: const Color(0xFF1E1E1E), borderRadius: BorderRadius.circular(14)),
            child: Text(_formatDateHeader(msgDate), style: const TextStyle(fontSize: 12, color: Colors.white70, fontWeight: FontWeight.w600, letterSpacing: 0.2)),
          ),
          wrappedBubble
        ],
      );
    }
    return wrappedBubble;
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: () async {
        if (activeContactId != null) {
          setState(() {
            activeContactId = null;
            _replyingTo = null; 
            _editingMsgId = null;
          });
          return false; 
        }
        return true; 
      },
      child: AnimatedSwitcher(
        duration: const Duration(milliseconds: 250),
        switchInCurve: Curves.easeOutCubic,
        switchOutCurve: Curves.easeInCubic,
        transitionBuilder: (child, animation) {
          final isChat = child.key == const ValueKey('chat_view');
          final offsetAnimation = Tween<Offset>(
            begin: isChat ? const Offset(1.0, 0.0) : const Offset(-0.2, 0.0), 
            end: Offset.zero,
          ).animate(animation);
          
          return FadeTransition(
            opacity: animation,
            child: SlideTransition(position: offsetAnimation, child: child),
          );
        },
        child: activeContactId == null ? _buildDashboardView() : _buildChatView(),
      ),
    );
  }
}

// ==========================================
// 3. PREMIUM ANIMATED LOGO WIDGET
// ==========================================
class WingsLogo extends StatefulWidget {
  final double size;
  const WingsLogo({super.key, this.size = 180});

  @override
  State<WingsLogo> createState() => _WingsLogoState();
}

class _WingsLogoState extends State<WingsLogo> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _glowAnimation;
  late Animation<double> _scaleAnimation;

  @override
  void initState() {
    super.initState();
    // Creates a smooth, continuous "breathing" loop
    _controller = AnimationController(vsync: this, duration: const Duration(seconds: 2))..repeat(reverse: true);
    
    // Significantly reduced glow opacity for a soft, ambient backlight
    _glowAnimation = Tween<double>(begin: 0.05, end: 0.15).animate(CurvedAnimation(parent: _controller, curve: Curves.easeInOut));
    _scaleAnimation = Tween<double>(begin: 0.98, end: 1.0).animate(CurvedAnimation(parent: _controller, curve: Curves.easeInOut));
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        return Transform.scale(
          scale: _scaleAnimation.value,
          child: Container(
            width: widget.size,
            height: widget.size,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: Colors.blueAccent.withOpacity(_glowAnimation.value),
                  blurRadius: 50, // Soft, wide spread
                  spreadRadius: 5,
                ),
              ],
            ),
            child: Image.asset(
              'assets/WingsLogo.png', 
              fit: BoxFit.contain,
              errorBuilder: (context, error, stackTrace) {
                return const Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.broken_image, color: Colors.redAccent, size: 32),
                      SizedBox(height: 8),
                      Text("Restart app to load image.", style: TextStyle(fontSize: 10, color: Colors.white54)),
                    ],
                  ),
                );
              },
            ),
          ),
        );
      },
    );
  }
}