using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Net;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Management;
using System.Diagnostics.Eventing.Reader;
using System.Web.Script.Serialization;
using System.Xml.Linq;

namespace Sedra.Agent {
 public static class Wire {
  public static readonly JavaScriptSerializer Json=new JavaScriptSerializer {MaxJsonLength=1048576,RecursionLimit=20};
  public static string Serialize(object x) { lock(Json)return Json.Serialize(x); }
  public static Dictionary<string,object> Parse(string x) { lock(Json)return Json.Deserialize<Dictionary<string,object>>(x); }
  public static string Hash(string x) { using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(x))).Replace("-","").ToLowerInvariant(); }
  public static double Now() { return (DateTime.UtcNow-new DateTime(1970,1,1)).TotalSeconds; }
  public static void Atomic(string path,string text) {
   string temp=path+".tmp";
   using(var f=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)) { byte[] bytes=Encoding.UTF8.GetBytes(text);f.Write(bytes,0,bytes.Length);f.Flush(true); }
   if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
  }
  public static string Str(Dictionary<string,object> d,string k) {return d.ContainsKey(k)&&d[k] is string?(string)d[k]:"";}
  public static bool Flag(Dictionary<string,object> d,string k) {return d.ContainsKey(k)&&d[k] is bool&&(bool)d[k];}
  public static string[] Strings(Dictionary<string,object> d,string k) {
   if(!d.ContainsKey(k))throw new Exception("Missing list");var a=d[k] as System.Collections.IEnumerable;if(a==null||d[k] is string)throw new Exception("Invalid list");
   var v=new List<string>();foreach(object x in a){if(!(x is string))throw new Exception("Invalid list");v.Add((string)x);}return v.ToArray();
  }
  public static bool Hex(string s,int n) {return s.Length==n&&s.All(c=>"0123456789abcdef".IndexOf(c)>=0);}
 }
 public sealed class Config {
  public Uri Server;public string Device,Subject,Sid,Binding;public string[] Directories,Processes;public int Poll;
  public static Config Read(string path) {
   var d=Wire.Parse(File.ReadAllText(path));string[] fields={"server_url","device_id","subject_id","target_user_sid","watch_directories","process_names","poll_seconds","allow_loopback_http","collect_usb","collect_session"};
   if(d.Keys.Except(fields).Any()||fields.Except(d.Keys).Any())throw new Exception("Closed config required");
   var c=new Config();c.Server=new Uri(Wire.Str(d,"server_url"),UriKind.Absolute);c.Device=Wire.Str(d,"device_id");c.Subject=Wire.Str(d,"subject_id");c.Sid=Wire.Str(d,"target_user_sid");new SecurityIdentifier(c.Sid);
   IPAddress address;bool loop=IPAddress.TryParse(c.Server.Host.Trim('[',']'),out address)&&IPAddress.IsLoopback(address);
   if(c.Server.Scheme!="https"&&!(c.Server.Scheme=="http"&&loop&&Wire.Flag(d,"allow_loopback_http")))throw new Exception("HTTPS required except explicit loopback test");
   if(!String.IsNullOrEmpty(c.Server.UserInfo)||!String.IsNullOrEmpty(c.Server.Query)||!String.IsNullOrEmpty(c.Server.Fragment)||c.Server.AbsolutePath!="/")throw new Exception("Pinned server origin required");
   if(!Wire.Hex(c.Device,32)||String.IsNullOrWhiteSpace(c.Subject)||c.Subject.Length>80)throw new Exception("Enrolled identity required");
   c.Directories=Wire.Strings(d,"watch_directories");c.Processes=Wire.Strings(d,"process_names").Select(x=>x.ToLowerInvariant()).ToArray();
   if(c.Directories.Length>8||c.Processes.Length>16||c.Processes.Any(x=>x.Length>80||!System.Text.RegularExpressions.Regex.IsMatch(x,"^[a-z0-9._-]{1,76}\\.exe$")))throw new Exception("Bounded explicit collection scope required");
   foreach(string folder in c.Directories){if(folder.StartsWith("\\\\")||!Path.IsPathRooted(folder)||!Directory.Exists(folder)||Path.GetPathRoot(folder)==Path.GetFullPath(folder))throw new Exception("Existing local non-root folder required");for(var part=new DirectoryInfo(folder);part!=null;part=part.Parent)if(part.Attributes.HasFlag(FileAttributes.ReparsePoint))throw new Exception("Reparse ancestors refused");}
   c.Poll=Convert.ToInt32(d["poll_seconds"]);if(c.Poll<5||c.Poll>60)throw new Exception("Poll interval 5 to 60 seconds required");
   c.Usb=Wire.Flag(d,"collect_usb");c.Session=Wire.Flag(d,"collect_session");
   c.Binding=Wire.Hash(c.Server.AbsoluteUri+"|"+c.Device+"|"+c.Subject);return c;
  }
  public bool Usb,Session;
 }
 public sealed class Engine:IDisposable {
  readonly string folder,spool;readonly Config config;readonly FileStream instance;readonly object gate=new object();readonly ManualResetEvent stop=new ManualResetEvent(false);
  readonly List<FileSystemWatcher> watchers=new List<FileSystemWatcher>();ManagementEventWatcher process;EventLogWatcher session;
  readonly Dictionary<string,string> coverage=new Dictionary<string,string>{{"files","disabled"},{"process","disabled"},{"usb","disabled"},{"session","disabled"}};
  readonly string secret,salt;string transport="starting";long dropped;int failures;bool usbSeen;double usbAt;HashSet<string> usb=new HashSet<string>();
  public Engine(string path) {
   folder=Path.GetFullPath(path);config=Config.Read(Path.Combine(folder,"config.json"));spool=Path.Combine(folder,"spool");Directory.CreateDirectory(spool);
   instance=new FileStream(Path.Combine(folder,"agent.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
   try {
    if(File.ReadAllText(Path.Combine(folder,"binding.txt"))!=config.Binding)throw new Exception("Identity binding changed; new enrollment directory required");
    secret=Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(Path.Combine(folder,"credential.dpapi")),Encoding.UTF8.GetBytes(config.Binding),DataProtectionScope.LocalMachine));
    salt=File.ReadAllText(Path.Combine(folder,"salt.txt"));
    if(!secret.StartsWith("sedra_k_")||secret.Length>200)throw new Exception("Credential unavailable");
    string state=Path.Combine(folder,"dropped.txt");if(File.Exists(state))dropped=Int64.Parse(File.ReadAllText(state));
   }catch{instance.Dispose();throw;}
  }
  string Fingerprint(string x){return Wire.Hash(salt+"|"+x);}
  void CountLoss(){dropped=Math.Min(Int32.MaxValue,dropped+1);Wire.Atomic(Path.Combine(folder,"dropped.txt"),dropped.ToString());}
  void Enqueue(string kind,Dictionary<string,object> detail,string id,double at) {
   lock(gate){
    if(stop.WaitOne(0))return;
    try {
     var files=new DirectoryInfo(spool).GetFiles();
     if(String.IsNullOrEmpty(id))id=Guid.NewGuid().ToString("N");string target=Path.Combine(spool,id+".json");if(File.Exists(target))return;
     string json=Wire.Serialize(new Dictionary<string,object>{{"event_id",id},{"occurred_at",at},{"kind",kind},{"detail",detail}});if(files.Length>=10000||files.Sum(f=>f.Length)+Encoding.UTF8.GetByteCount(json)>8*1024*1024){CountLoss();return;}Wire.Atomic(target,json);
    }catch{transport="local_storage_error";coverage["files"]="overflow";}
   }
  }
  public void StartCollectors() {
   foreach(string dir in config.Directories){try {
    var w=new FileSystemWatcher(dir);w.IncludeSubdirectories=false;w.NotifyFilter=NotifyFilters.FileName|NotifyFilters.LastWrite|NotifyFilters.Size;w.InternalBufferSize=16384;
    FileSystemEventHandler handler=(s,e)=>Enqueue("file_changed",new Dictionary<string,object>{{"file_fingerprint",Fingerprint(Path.GetFullPath(e.FullPath).ToLowerInvariant())},{"operation",e.ChangeType.ToString().ToLowerInvariant()}},null,Wire.Now());
    w.Created+=handler;w.Changed+=handler;w.Deleted+=handler;
    w.Renamed+=(s,e)=>Enqueue("file_changed",new Dictionary<string,object>{{"file_fingerprint",Fingerprint(Path.GetFullPath(e.FullPath).ToLowerInvariant())},{"operation","renamed"}},null,Wire.Now());
    w.Error+=(s,e)=>{lock(gate){coverage["files"]="overflow";CountLoss();}};w.EnableRaisingEvents=true;watchers.Add(w);coverage["files"]="connected";
   }catch{coverage["files"]="unavailable";}}
   if(config.Processes.Length>0)try {
    process=new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace WHERE "+String.Join(" OR ",config.Processes.Select(x=>"ProcessName='"+x+"'"))));
    process.EventArrived+=(s,e)=>{try {
     string name=Convert.ToString(e.NewEvent["ProcessName"]).ToLowerInvariant();if(!config.Processes.Contains(name))return;
     byte[] sid=e.NewEvent["Sid"] as byte[];if(sid==null||new SecurityIdentifier(sid,0).Value!=config.Sid)return;
     double at=(DateTime.FromFileTimeUtc(Convert.ToInt64(e.NewEvent["TIME_CREATED"]))-new DateTime(1970,1,1)).TotalSeconds;
     string id=Wire.Hash("process|"+e.NewEvent["ProcessID"]+"|"+at.ToString("R",System.Globalization.CultureInfo.InvariantCulture));
     Enqueue("process_started",new Dictionary<string,object>{{"process_fingerprint",Fingerprint(id)},{"name_fingerprint",Fingerprint(name)}},id,at);
    }catch{lock(gate)coverage["process"]="unavailable";}};process.Start();coverage["process"]="connected";
   }catch{coverage["process"]="unavailable";}
   if(config.Session)try {
    string account=new SecurityIdentifier(config.Sid).Translate(typeof(NTAccount)).Value;
    string channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    var q=new EventLogQuery(channel,PathType.LogName,"*[System[(EventID=21 or EventID=23 or EventID=24 or EventID=25)]]");
    // Subscribe to future session events only; service downtime is a capture gap.
    session=new EventLogWatcher(q);
    session.EventRecordWritten+=(s,e)=>{
     if(e.EventException!=null){lock(gate)coverage["session"]="unavailable";return;}using(var record=e.EventRecord){if(record==null)return;
      try {
       var xml=XDocument.Parse(record.ToXml());string user=xml.Descendants().Where(x=>x.Name.LocalName=="User").Select(x=>x.Value).FirstOrDefault();
       if(String.Equals(user,account,StringComparison.OrdinalIgnoreCase)&&record.TimeCreated.HasValue){string kind=record.Id==21?"session_logon":record.Id==23?"session_logoff":record.Id==24?"session_disconnect":"session_reconnect";
        string id=Wire.Hash(channel+"|"+record.RecordId+"|"+record.TimeCreated.Value.ToUniversalTime().Ticks);double at=(record.TimeCreated.Value.ToUniversalTime()-new DateTime(1970,1,1)).TotalSeconds;
        Enqueue(kind,new Dictionary<string,object>{{"event_fingerprint",Fingerprint(id)}},id,at);
       }
       // No fabricated session snapshot or historical logon is emitted.

      }catch{lock(gate)coverage["session"]="unavailable";}
     }
    };session.Enabled=true;coverage["session"]="connected";
   }catch{coverage["session"]="unavailable";}
  }
  void PollUsb() {
   if(!config.Usb)return;
   try {
    var seen=new HashSet<string>();using(var query=new ManagementObjectSearcher("SELECT PNPDeviceID,InterfaceType FROM Win32_DiskDrive"))using(var results=query.Get())foreach(ManagementObject d in results) {
     string id=Convert.ToString(d["PNPDeviceID"]);if(Convert.ToString(d["InterfaceType"])=="USB"||id.StartsWith("USBSTOR\\",StringComparison.OrdinalIgnoreCase))seen.Add(Fingerprint(id));
    }
    double now=Wire.Now();bool continuous=usbSeen&&now-usbAt<=Math.Max(30,config.Poll*2);
    foreach(string id in seen.Except(usb))Enqueue(continuous?"usb_arrival":"usb_baseline",new Dictionary<string,object>{{"device_fingerprint",id}},null,now);
    if(continuous)foreach(string id in usb.Except(seen))Enqueue("usb_removal",new Dictionary<string,object>{{"device_fingerprint",id}},null,now);
    usb=seen;usbSeen=true;usbAt=now;lock(gate)coverage["usb"]="connected";
   }catch{usbSeen=false;lock(gate)coverage["usb"]="unavailable";}
  }
  bool Flush() {
   var batch=new List<Dictionary<string,object>>();var paths=new List<string>();Dictionary<string,string> cov;long lost;
   lock(gate){
    foreach(string path in new DirectoryInfo(spool).GetFiles("*.json").OrderBy(x=>x.CreationTimeUtc).ThenBy(x=>x.Name).Take(50).Select(x=>x.FullName)){
     try {
      var item=Wire.Parse(File.ReadAllText(path));string id=Wire.Str(item,"event_id");if(!Wire.Hex(id,32)&&!Wire.Hex(id,64))throw new Exception();
      if(Path.GetFileNameWithoutExtension(path)!=id)throw new Exception();
      if(Convert.ToDouble(item["occurred_at"])<Wire.Now()-6*86400){File.Delete(path);CountLoss();continue;}
      batch.Add(item);paths.Add(path);
     }catch{transport="spool_invalid";return false;}
    }
    cov=new Dictionary<string,string>(coverage);lost=dropped;
   }
   try {
    var body=new Dictionary<string,object>{{"device_id",config.Device},{"subject_id",config.Subject},{"events",batch},{"coverage",cov},{"dropped",lost}};
    byte[] bytes=Encoding.UTF8.GetBytes(Wire.Serialize(body));var req=(HttpWebRequest)WebRequest.Create(new Uri(config.Server,"/api/v1/endpoint/events"));
    req.Method="POST";req.ContentType="application/json";req.Headers["Authorization"]="Bearer "+secret;req.AllowAutoRedirect=false;req.Proxy=null;req.Timeout=10000;req.ReadWriteTimeout=10000;req.ContentLength=bytes.Length;
    using(var stream=req.GetRequestStream())stream.Write(bytes,0,bytes.Length);
    using(var response=(HttpWebResponse)req.GetResponse()) {
     if(response.StatusCode!=HttpStatusCode.OK){transport="http_"+(int)response.StatusCode;return false;}
     if(response.ContentLength>65536)throw new Exception("Response bound");string text;
     using(var stream=response.GetResponseStream())using(var reader=new StreamReader(stream,Encoding.UTF8)){char[] chars=new char[65537];int total=0,n;while(total<chars.Length&&(n=reader.Read(chars,total,chars.Length-total))>0)total+=n;if(total>65536)throw new Exception("Response bound");text=new string(chars,0,total);}
     var ack=Wire.Parse(text);string[] ids=Wire.Strings(ack,"acked_event_ids");var expected=batch.Select(x=>Wire.Str(x,"event_id")).OrderBy(x=>x).ToArray();
     if(Wire.Str(ack,"device_id")!=config.Device||Wire.Str(ack,"origin")!="AUTHENTICATED_ENDPOINT_REPORT"||!(ack["accepted"] is int)||!(ack["duplicates"] is int)||(int)ack["accepted"]<0||(int)ack["duplicates"]<0||(int)ack["accepted"]+(int)ack["duplicates"]!=batch.Count||!ids.OrderBy(x=>x).SequenceEqual(expected))throw new Exception("Unbound acknowledgment");
     lock(gate)foreach(string path in paths)File.Delete(path);
     transport="connected";return true;
    }
   }catch(WebException e){var r=e.Response as HttpWebResponse;transport=r==null?"network_unavailable":"http_"+(int)r.StatusCode;if(r!=null)r.Dispose();return false;}
   catch{transport="invalid_response";return false;}
  }
  void Status() {lock(gate)Wire.Atomic(Path.Combine(folder,"status.json"),Wire.Serialize(new {version="0.20.0",device_id=config.Device,subject_id=config.Subject,at=Wire.Now(),transport=transport,queued=Directory.GetFiles(spool,"*.json").Length,dropped=dropped,coverage=new Dictionary<string,string>(coverage),scope="Configured nonrecursive directories, allowlisted target-SID processes, USB presence and target-account session events; no contents or command lines"}));}
  public void Run(int seconds) {
   StartCollectors();double until=seconds>0?Wire.Now()+seconds:Double.MaxValue;
   try {while(!stop.WaitOne(0)&&Wire.Now()<until){PollUsb();bool ok=Flush();failures=ok?0:Math.Min(failures+1,6);Status();int delay=ok?config.Poll:Math.Min(300,config.Poll*(1<<failures));int wait=seconds>0?Math.Min(delay,Math.Max(0,(int)Math.Ceiling(until-Wire.Now()))):delay;stop.WaitOne(wait*1000);}}
   finally {StopCollectors();transport="stopped";Status();}
  }
  void StopCollectors(){foreach(var w in watchers)w.Dispose();watchers.Clear();if(process!=null){try{process.Stop();}catch{}process.Dispose();process=null;}if(session!=null){session.Dispose();session=null;}}
  public void Stop(){stop.Set();}
  public void Dispose(){stop.Set();StopCollectors();instance.Dispose();stop.Dispose();}
 }
 public sealed class Service:ServiceBase {
  readonly string folder;Engine engine;Thread thread;
  public Service(string path,string name){folder=path;ServiceName=name;CanStop=true;CanShutdown=true;AutoLog=false;}
  protected override void OnStart(string[] args){engine=new Engine(folder);thread=new Thread(()=>{try{engine.Run(0);}catch{Environment.Exit(1);}});thread.IsBackground=true;thread.Start();}
  protected override void OnStop(){RequestAdditionalTime(25000);engine.Stop();if(!thread.Join(20000))throw new Exception("Agent stop pending");engine.Dispose();}
  protected override void OnShutdown(){OnStop();}
 }
 public static class Program {
  public static int Main(string[] args) {
   ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
   try {
    if(args.Length==3&&args[0]=="provision"){
     string folder=Path.GetFullPath(args[1]);Config config=Config.Read(args[2]);Directory.CreateDirectory(folder);
     using(var guard=new FileStream(Path.Combine(folder,"agent.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)){
      string bindingPath=Path.Combine(folder,"binding.txt");if(File.Exists(bindingPath)&&File.ReadAllText(bindingPath)!=config.Binding)throw new Exception("Existing binding differs");
      string token=Console.ReadLine();if(token==null||token.Length>200||!System.Text.RegularExpressions.Regex.IsMatch(token,"^sedra_k_[0-9a-f]{16}\\.[A-Za-z0-9_-]{40,}$"))throw new Exception("Credential required on stdin");
      byte[] protectedBytes=ProtectedData.Protect(Encoding.UTF8.GetBytes(token),Encoding.UTF8.GetBytes(config.Binding),DataProtectionScope.LocalMachine);
      File.WriteAllBytes(Path.Combine(folder,"credential.dpapi"),protectedBytes);Wire.Atomic(bindingPath,config.Binding);
      string source=Path.GetFullPath(args[2]),target=Path.Combine(folder,"config.json");if(source!=target)Wire.Atomic(target,File.ReadAllText(source));
      if(!File.Exists(Path.Combine(folder,"salt.txt"))){byte[] salt=new byte[32];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(salt);Wire.Atomic(Path.Combine(folder,"salt.txt"),Convert.ToBase64String(salt));}
     }
     Console.WriteLine("Provisioned; credential encrypted, no service installed.");return 0;
    }
    if(args.Length>=2&&args[0]=="--console"){
     int seconds=args.Length==3?Int32.Parse(args[2]):0;if(seconds<0||seconds>86400)throw new Exception();
     using(var engine=new Engine(args[1])){Console.CancelKeyPress+=(s,e)=>{e.Cancel=true;engine.Stop();};engine.Run(seconds);}return 0;
    }
    if(args.Length==3&&args[0]=="--service"){ServiceBase.Run(new Service(args[1],args[2]));return 0;}
    Console.WriteLine("SEDRA Windows Agent 0.20.0 | provision <data-dir> <config.json> (key on stdin) | --console <data-dir> [seconds] | --service <data-dir> <service-name>");return 2;
   }catch{Console.Error.WriteLine("Agent could not start/provision. Check bounded configuration, data ACL, enrollment binding and credential. Secret values are not printed.");return 1;}
  }
 }
}
