package burp.ui;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Font;

/** 「帮助」页：使用步骤与原理说明（离线可读，不依赖外部文档）。 */
public final class HelpPanel extends JPanel {

    private static final String TEXT = """
            BurpCryptCat · Body 透明加解密
            ============================

            【一、三步开始用】
              1) 「配置方案」页：选择算法（例如 AES/CBC/PKCS5Padding），填 Key、IV，
                 选密文编码（Base64 / HEX / 原始二进制），点「保存并应用」。
                 右下角测试台可以先粘一段真实密文点「→ 解密」验证能不能解出来。
              2) 「生效规则」页：新增一条规则，匹配方式选 Host（如 api.example.com）
                 或 URL 通配（如 https://api.example.com/gw/*），选择刚才的方案，勾选启用。
              3) 正常抓包：Repeater / Intruder 里对着明文改、对明文爆破，插件自动
                 加密后发出、自动解密响应。

            【二、四个位置分别发生了什么】
              Proxy 请求：客户端密文 → 解密后交给 Burp（Original 保留原始密文 / Edited 是解密后的明文）
                          明文在「BurpCryptCat明文」页签里看/改 → 真正上线前由 HttpHandler 加密 → 服务端收到密文
              Proxy 响应：报文不动（Burp 里就是服务端原始响应）
                          明文在「BurpCryptCat明文（响应）」页签 / 明文查看器里看
              Repeater  ：发出去之前自动加密（编辑器里可以是明文）；响应自动解密后展示
              Intruder  ：每个变异包按明文插入 Payload，发出前整包加密；响应自动解密
              只动 Body：URL、Header、Cookie 一个字节都不改（Content-Length 由报文对象维护）。

            【三、重要：为什么 Proxy 历史里默认是密文】
              Burp 的 Proxy 历史保存的就是"最终上线/回写的那份报文"，扩展能改的
              报文和 Burp 存起来的报文是同一份。所以：
                · 想"历史显示明文"  → 客户端/服务端必然收到明文
                · 想"两端仍是密文"  → 历史里必然是密文
              两者在 Burp 里无法同时成立（这是 Burp 的机制，不是配置问题）。
              本插件的默认取舍是"两端保持密文"（更安全，不影响目标程序），
              同时在「全局设置」里给了两个开关：
                [√] 请求放行前重新加密（服务端收到密文）
                [√] 响应回写前重新加密（客户端收到密文）
              把某个开关去掉 → 该方向历史立刻显示明文，代价是那一端收到明文
              （适合用 Burp 自己发包、不需要目标 App 正常工作的场景）。

              默认模式下怎么看 Proxy 里的明文？
                · 请求侧：报文编辑器左上角的"报文类型"下拉，Original request（原始密文）/
                  Edited request（解密后的明文，即本页签）；默认显示哪版可在 Settings → Proxy →
                  Default Proxy history message display 里设
                也可以看下面这几处：
                · 报文编辑器里的「BurpCryptCat明文」页签：**完整报文**
                  （请求行 + 全部 Header + 解密后的 Body），URL/Header 原样保留，
                  Content-Length 按明文长度重算，JSON 自动缩进美化；
                  可以像普通报文一样直接改，发送时自动加密回去。
                · 「③ 明文查看器」的实时流水
                · 右键 →「BurpCryptCat：解密后发送到 Repeater / Intruder」
                · 右键 →「BurpCryptCat：查看明文」（同样是完整报文）

            【四、让其它插件（xia SQL / Scanner）也自动加解密】
              到「④ 全局设置」勾上最上面的顶层开关：
                  [√] 对所有工具生效（Proxy / Repeater / Intruder / Scanner / 其它插件）
              之后 xia SQL 这类插件发的请求会在发出前自动加密，收到的响应自动解密后再交给它。
              前提：喂给插件的"请求模板"本身要是明文，否则它会把 Payload 塞进 base64 里。
              两种做法（任选）：
                · 去掉「请求放行前重新加密」→ Proxy 历史里是明文，插件从历史取到的就是明文模板
                · 不关开关，从「BurpCryptCat明文」页签 / 右键「解密后发送到 Repeater」出发

            【五、脚本方式（四个阶段接口）】
              「① 配置方案 → 加解密方式」里有四种：
                · 内置算法       ：填算法/Key/IV（上面讲的那套）
                · 脚本(JavaScript)：实现四个同名函数（camelCase），插件在对应阶段调用
                · 脚本(Python)   ：实现四个 snake_case 函数；默认用环境自带的 python3，
                                   也可以手动指定解释器 / venv 里的 python（先做 py_compile 语法检查）
                · 外部命令       ：Body 从 stdin 进、新 Body 从 stdout 出，任何语言都能写

              四个接口严格对应 Burp 的四个阶段：
                function clientToBurp(ctx) {}   // ① 客户端 → Burp（Proxy 收到请求，一般解密）
                function burpToServer(ctx) {}   // ② Burp → 服务端（请求放行前，一般加密）
                function serverToBurp(ctx) {}   // ③ 服务端 → Burp（收到响应，一般解密）
                function burpToClient(ctx) {}   // ④ Burp → 客户端（响应回写前，一般加密）
              只实现需要的接口即可，没实现的阶段会被跳过。

              Python 版函数名（snake_case）：
                def client_to_burp(ctx): ...    ① 客户端 → Burp
                def burp_to_server(ctx): ...    ② Burp → 服务端
                def server_to_burp(ctx): ...    ③ 服务端 → Burp
                def burp_to_client(ctx): ...    ④ Burp → 客户端
              ctx 上有 body / raw_body / charset / url / method / is_request /
              headers / header("x-iv") / stage / stage_code / log(msg)。
              返回字符串=新 Body，None=不改动。Python 进程是常驻的，改脚本保存即生效。

              ctx 上有什么：
                ctx.body / charset / url / method / isRequest / stage / stageCode
                ctx.headers                 全部 Header（"Name: value" 数组）
                ctx.header("x-iv")          取某个 Header（大小写不敏感）
                ctx.log("...")              打到 Extender → Output

              返回值：字符串 = 新 Body；null = 不改动；{ body: "..." } 也行。
              脚本里直接能用的工具（不用装第三方库）：
                JS 里是 crypto.*，Python 里是同名模块 crypto（snake_case，import crypto 也行）
                编码：Base64 / URL-safe Base64 / HEX（含大写）/ URL 编解码 / 原始字节互转
                摘要：md5 / sha1 / sha256 / sha512；HMAC-MD5 / SHA1 / SHA256
                对称：AES-CBC（含随机 IV 前置）、AES-ECB、SM4-CBC、DES-CBC、3DES-CBC
                杂项：randomHex / randomBytes / uuid / now；Python 还有 pkcs7_pad / pkcs7_unpad
                Python 侧的 AES/SM4 是内置纯 Python 实现，不需要 pip install
                Key/IV 支持 Base64 或 UTF-8 原文；失败时 JS 返回 null、Python 抛异常

              怎么开始：「加解密方式」选「脚本(JavaScript)」→ 点「生成模板」，
                会在 ~/.BurpCrypto/scripts/ 下生成带四个接口和注释的 .js 文件；
                改完点「自检」，下面会显示"已实现钩子（n/4）"。
              外部命令模式：把命令行填进「脚本/命令」，例如 python3 ~/.BurpCrypto/scripts/gm.py
              Python 解释器：在「④ 全局设置 → Python 解释器」里配（留空=自动找 python3/python）

              注意：脚本拥有与 Burp 相同的权限，只运行你信任的脚本。

            【六、常见配置对应关系】
              密文是 "U2FsdGVk..." 这种          → 密文编码 Base64
              密文是 "8f2a1c..."（0-9a-f）        → 密文编码 HEX
              密文是 {"data":"9f8e..."}            → 处理范围选「JSON 字段」，字段名填 data
              每包 IV 都不一样、密文开头自带 IV   → IV 模式选「随机 IV 前置（IV||CT）」（或直接用「自动」）
              不知道是哪种、或解出来"前面一段乱码" → IV 模式选「自动」，IV 可留空
              密钥是 32 位 hex 字符串              → Key 格式选 HEX（或留 自动识别）
              密钥是 16 位明文口令                 → Key 格式选 文本(UTF-8)

            【七、判定逻辑（为什么不会把流量搞坏）】
              插件对每段 Body 做"试探性解密"：能解出可读文本 → 认为是密文；否则认为是明文。
              因此同一个报文被反复处理也不会被加密两次；解不开的一律原样放行。
              日志里出现"填充错误/解密失败"基本就是 Key、IV、算法或编码选错了，
              用测试台逐个排查即可。

            【八、支持的算法】
              AES     ：ECB / CBC / CFB / OFB / CTR / GCM，PKCS5(7) / NoPadding / ZeroPadding / ISO10126
              SM4     ：ECB / CBC / CFB / OFB / CTR（内置实现，无需装 BouncyCastle）
              DES     ：ECB / CBC / CFB / OFB / CTR
              3DES    ：DESede + 上述模式
              RC4     、ChaCha20
              另有「自定义」：算法下拉框可直接手打任意 JCE transformation，
              例如 AES/CBC/PKCS5Padding、SM4/CBC/PKCS5Padding、AES/GCM/NoPadding。

            美化开关：「④ 全局设置 → 明文页签里美化 JSON」。关掉后就是原始单行 JSON。

            【九、在 Proxy / Repeater 里直接编辑明文】
              点开任意一条命中规则的报文，报文编辑器里会多出明文页签：
                · 请求页签「BurpCryptCat明文」：解密后的完整请求（请求行 + Header + 明文 Body）
                · 响应页签「BurpCryptCat明文（响应）」：解密后的完整响应
               请求侧看哪一版由 Burp 报文编辑器自己的"报文类型"下拉决定（插件不另加控件）：
                Original request —— 原始请求，未经修改（客户端发出的原始密文）
                Edited request   —— 解密后的明文（= 本页签的内容；你改的也计入这一版）
              请求的加密放在真正上线前的 HttpHandler 里，所以 Burp 里这条请求一直是明文、
              下拉一定有得切；线上发出时仍是密文。
              在页签里改的内容会被加密（改过的内容也算）；切回 Original 再放行则一个字节都不动。
              响应侧默认不动报文（Burp 里只有 Original response，明文只在本页签/流水里）；
              想让响应也显示明文，把「响应回写前重新加密」关掉（客户端会收到明文）。
              Proxy 历史默认显示哪一版：Settings → Proxy → Default Proxy history message display。

            【十、配置存在哪】
              方案与全局开关：~/.BurpCrypto/config
              生效规则      ：~/.BurpCrypto/rules（单独一份，方便备份/手改/进 git）
              默认目录：~/.BurpCrypto/（Windows：C:\\Users\\<你>\\.BurpCrypto\\），
              同目录还有 config.bak（上一次的备份）与 status.txt（当前生效状态，排错用）。
              「④ 全局设置」第一行可以「选择目录…」换地方（换项目/换盘），也能「重新载入」。
              首次升级会自动把旧版存在 Burp Preferences 里的配置迁移过来。

            【十一、排错】
              · 总开关/规则/方案任一没启用 → 什么都不发生（顶部状态栏会提示原因）
              · Repeater 发出的还是明文 → 确认该 URL 命中了规则，且方案已启用
              · 解密出来是乱码 → Key/IV/算法/编码不匹配；先用测试台核对
              · 只有"前 16 字节乱码、后面全是正常 JSON" → 密文是 IV||CT 结构
                （真 IV 在报文体最前面），把 IV 模式改成「自动」即可
              · 想看每一步的判断 → 「全局设置」勾选调试日志，到 Extender → Output 查看

            【十二、安全提醒】
              配置（含密钥）保存在 Burp 的 Preferences 里，属于明文存储。
              共享 Burp 项目文件/配置给别人前，请先清空 Key。
            """;

    public HelpPanel(UiContext ctx) {
        super(new BorderLayout());
        setBorder(new EmptyBorder(10, 12, 10, 12));
        JTextArea area = new JTextArea(TEXT);
        area.setEditable(false);
        area.setLineWrap(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setCaretPosition(0);
        JScrollPane sp = new JScrollPane(area);
        add(sp, BorderLayout.CENTER);
    }
}
