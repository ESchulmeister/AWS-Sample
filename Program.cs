    using System;
    using System.Configuration;
    using System.Collections.Specialized;
    using System.Text;
    using Amazon;
    using Amazon.S3;
    using Amazon.S3.Model;
    using Amazon.CloudFront;
    using Amazon.CloudFront.Model;
    using System.Security.Cryptography;
    using System.Xml;
    using System.IO;
    using System.Collections.Generic ;
    using System.Reflection;


namespace AWS_PrivateCF_Distributions
{
    class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length==0)
            {
                ListMethods();
                return;
            }

            switch (args[0])
            {
                case "CreateCannedPrivateURL":
                    string privateUrlCanned = CreateCannedPrivateURL(args[1], args[2], args[3],
                        args[4], args[5], args[6]);
                    // args[] 0-thisMethod, 1-resourceUrl, 2-seconds-minutes-hours-days to expiration, 
                    // 3-numberOfargs[2], 4-pathToPolicyStmt, 5-pathToPrivateKey, 6-privateKeyId
                    Console.Write("Private URL:\n" + privateUrlCanned + "\n");
                    break;

                case "CreateCustomPrivateURL":
                    // args[] 0-thisMethod, 1-resourceUrl, 2-seconds-minutes-hours-days to expiration, 
                    // 3-numberOfargs[2], 4-starttimeFromNow, 5-ip_address, 6-pathToPolicyStmt, 7-pathToPrivateKey, 8-privateKeyId
                    string privateUrlCustom = CreateCustomPrivateURL(args[1], args[2], args[3],
                        args[4], args[5], args[6], args[7], args[8]);
                    Console.Write("Private URL:\n" + privateUrlCustom + "\n");
                    break;

                case "creates3bucket":
                    CreateS3V2Bucket(args[1]);
                    break;

                case "puts3items":
                    PutS3ItemInBucket(args[1], args[2]);
                    break;

                case "PutS3CanonicalUserIdACL":
                    PutS3CanonicalUserIdACL(args[1], args[2], args[3]);
                    break;

                case "ListObjectsOwner":
                    ListObjectsWithOwner(args[1], args[2]);
                    break;

                case "CreatePrivateDistributionWithSigners":
                    List<string> signers = new List<string>();
                    for(int i=4; i<args.Length; i++)
                        signers.Add(args[i]);                        
                    CreatePrivateDistributionWithSigners(args[1], args[2], args[3], signers);
                    break;

                case "ReadDistSigners":
                    ReadDistributionSigners(args[1]);
                    break;                

                default:
                    ListMethods();
                    Console.Read();
                    break;
            }
            Console.WriteLine("Any key to end... ");
            Console.Read();
        }

        /// <summary>
        /// Base64-encodes the specified bytes, and then replaces
        /// <c> +, =, / </c> with <c> -, _, ~ </c> respectively,
        /// thus making the returned encoded string safe to use as
        /// a URL query argument.
        /// </summary>
        public static string ToUrlSafeBase64String(byte[] bytes)
        {
            return System.Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('=', '_')
                .Replace('/', '~');
        }

        public static string CreateCannedPrivateURL(string urlString, string durationUnits,
            string durationNumber, string pathToPolicyStmnt, string pathToPrivateKey, string privateKeyId)
        {
            // args[] 0-thisMethod, 1-resourceUrl, 2-seconds-minutes-hours-days to expiration, 3-numberOfPreviousUnits, 
            // 4-pathToPolicyStmnt, 5-pathToPrivateKey, 6-PrivateKeyId

            TimeSpan timeSpanInterval = GetDuration(durationUnits, durationNumber);

            // Create the policy statement.
            string strPolicy = CreatePolicyStatement(pathToPolicyStmnt,
                urlString, DateTime.Now, DateTime.Now.Add(timeSpanInterval), "0.0.0.0/0");
            if ("Error!" == strPolicy) return "Invalid time frame.  Start time cannot be greater than end time.";

            // Copy the expiration time defined by policy statement.
            string strExpiration = CopyExpirationTimeFromPolicy(strPolicy);

            // Read the policy into a byte buffer.
            byte[] bufferPolicy = Encoding.ASCII.GetBytes(strPolicy);

            // Initialize the SHA1CryptoServiceProvider object and hash the policy data.
            using (SHA1CryptoServiceProvider cryptoSHA1 = new SHA1CryptoServiceProvider())
            {
                bufferPolicy = cryptoSHA1.ComputeHash(bufferPolicy);

                // Initialize the RSACryptoServiceProvider object.
                RSACryptoServiceProvider providerRSA = new RSACryptoServiceProvider();
                XmlDocument xmlPrivateKey = new XmlDocument();

                // Load the PrivateKey.xml file generated by ConvertPEMtoXML.
                xmlPrivateKey.Load(pathToPrivateKey);

                // Format the RSACryptoServiceProvider providerRSA and create the signature.
                providerRSA.FromXmlString(xmlPrivateKey.InnerXml);
                RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(providerRSA);
                rsaFormatter.SetHashAlgorithm("SHA1");
                byte[] signedPolicyHash = rsaFormatter.CreateSignature(bufferPolicy);

                // Convert the signed policy to URL safe base 64 encoding.
                string strSignedPolicy = ToUrlSafeBase64String(signedPolicyHash);

                // Concatenate the URL, the timestamp, the signature, and the key pair ID to form the private URL.
                return urlString + "?Expires=" + strExpiration + "&Signature=" + strSignedPolicy + "&Key-Pair-Id=" + privateKeyId;
            }
        }

        public static string CreateCustomPrivateURL(string urlString, string durationUnits,
            string durationNumber, string startIntervalFromNow, string ipaddress, string pathToPolicyStmnt,
            string pathToPrivateKey, string PrivateKeyId)
        {
            // args[] 0-thisMethod, 1-resourceUrl, 2-seconds-minutes-hours-days to expiration, 
            // 3-numberOfPreviousUnits, 4-starttimeFromNow, 5-ip_address, 6-pathToPolicyStmt, 7-pathToPrivateKey, 8-privateKeyId

            TimeSpan timeSpanInterval = GetDuration(durationUnits, durationNumber);
            TimeSpan timeSpanToStart = GetDurationByUnits(durationUnits, startIntervalFromNow);
            if (null == timeSpanToStart) 
                return "Invalid duration units. Valid options: seconds, minutes, hours, or days";
            
            string strPolicy = CreatePolicyStatement(
                pathToPolicyStmnt, urlString, DateTime.Now.Add(timeSpanToStart), DateTime.Now.Add(timeSpanInterval), ipaddress);

            // Read the policy into a byte buffer.
            byte[] bufferPolicy = Encoding.ASCII.GetBytes(strPolicy);

            // Base64 encode URL-safe policy statement.
            string urlSafePolicy = ToUrlSafeBase64String(bufferPolicy);

            // Initialize the SHA1CryptoServiceProvider object and hash the policy data.
            byte[] bufferPolicyHash;
            using (SHA1CryptoServiceProvider cryptoSHA1 = new SHA1CryptoServiceProvider())
            {
                bufferPolicyHash = cryptoSHA1.ComputeHash(bufferPolicy);

                // Initialize the RSACryptoServiceProvider object.
                RSACryptoServiceProvider providerRSA = new RSACryptoServiceProvider();
                XmlDocument xmlPrivateKey = new XmlDocument();

                // Load the PrivateKey.xml file generated by ConvertPEMtoXML.
                xmlPrivateKey.Load("PrivateKey.xml");

                // Format the RSACryptoServiceProvider providerRSA and create the signature.
                providerRSA.FromXmlString(xmlPrivateKey.InnerXml);
                RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(providerRSA);
                RSAFormatter.SetHashAlgorithm("SHA1");
                byte[] signedHash = RSAFormatter.CreateSignature(bufferPolicyHash);

                // Convert the signed policy to URL safe base 64 encoding.
                string strSignedPolicy = ToUrlSafeBase64String(signedHash);

                return urlString + "?Policy=" + urlSafePolicy + "&Signature=" + strSignedPolicy + "&Key-Pair-Id=" + PrivateKeyId;
            }
        }

        public static string CreateOriginAccessIdentity()
        {
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonCloudFrontClient client = AWSClientFactory.CreateAmazonCloudFrontClient(
                    appConfig["AWSAccessKey"],
                    appConfig["AWSSecretKey"]
                    ) as AmazonCloudFrontClient;

            CloudFrontOriginAccessIdentityConfig config = new CloudFrontOriginAccessIdentityConfig();
            config.CallerReference = "mycallerreference: " + DateTime.Now;
            config.Comment = "Caller reference: " + DateTime.Now;
            config.ETag = "tag: " + DateTime.Now;

            CreateOriginAccessIdentityRequest request = new CreateOriginAccessIdentityRequest();
            request.OriginAccessIdentityConfig = config;

            request.Marker = "marker: " + DateTime.Now;

            CreateOriginAccessIdentityResponse response = client.CreateOriginAccessIdentity(request);

            Console.WriteLine("Origin Access Id: " + response.OriginAccessIdentity);
            Console.WriteLine("S3CanonicalUserId: " + response.OriginAccessIdentity.S3CanonicalUserId);
            Console.WriteLine("ETag: " + response.OriginAccessIdentity.ETag);
            Console.WriteLine("Response XML: " + response.XML);
            Console.WriteLine("Config.CallerReference: " + response.OriginAccessIdentity.OriginAccessIdentityConfig.CallerReference);

            return response.OriginAccessIdentity.S3CanonicalUserId;
        }

        public static void CreatePrivateDistributionWithSigners(string originAcccessIdentity, 
            string dnsName, string withSelf, List<string> signerAccountIds)
        {
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonCloudFrontClient client = AWSClientFactory.CreateAmazonCloudFrontClient(
            appConfig["AWSAccessKey"],
            appConfig["AWSSecretKey"]
            ) as AmazonCloudFrontClient;

            CloudFrontDistributionConfig distConfig = new CloudFrontDistributionConfig();
            UrlTrustedSigners trustedSigners = new UrlTrustedSigners();

            trustedSigners.WithAwsAccountNumbers(signerAccountIds.ToArray());
            trustedSigners.WithEnableSelf(bool.Parse(withSelf));
            distConfig.TrustedSigners = trustedSigners;

            CloudFrontOriginAccessIdentity identity = new CloudFrontOriginAccessIdentity();
            identity.Id = originAcccessIdentity;

            S3Origin origin = new S3Origin();
            origin.OriginAccessIdentity = identity;
            origin.DNSName = dnsName;

            origin.WithOriginAccessIdentity(identity);
            distConfig.S3Origin = origin;
            CloudFrontDistribution distribution = new CloudFrontDistribution();
            distribution.DistributionConfig = distConfig;

            CreateDistributionRequest distRequest = new CreateDistributionRequest();
            distRequest.DistributionConfig = distConfig;

            try
            {
                CreateDistributionResponse response = client.CreateDistribution(distRequest);
                Console.WriteLine("Status: " + response.Distribution.Status);
                Console.WriteLine("Domain name: " + response.Distribution.DomainName);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        public static void ReadDistributionSigners(string DistributionID)
        {
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonCloudFrontClient client = AWSClientFactory.CreateAmazonCloudFrontClient(
            appConfig["AWSAccessKey"],
            appConfig["AWSSecretKey"]
            ) as AmazonCloudFrontClient;

            GetDistributionInfoRequest distRequest = new GetDistributionInfoRequest();
            distRequest.WithId(DistributionID);

            GetDistributionInfoResponse distResponse = client.GetDistributionInfo(distRequest);

            Console.WriteLine("Signers count: " + distResponse.Distribution.ActiveTrustedSigners.Count);
            foreach (Signer signer in distResponse.Distribution.ActiveTrustedSigners)
            {
                if (signer.Self)
                    Console.WriteLine("Self");
                Console.WriteLine(signer.AwsAccountNumber);
                foreach (object o in signer.KeyPairId)
                {
                    Console.WriteLine(o);
                }
            }
        }

        public static void CreateS3V2Bucket(string bucketName) // V2 bucket names must be all lower case.
        {
            // need V2 bucket for CF private distribution.
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonS3Client client = AWSClientFactory.CreateAmazonS3Client(
                    appConfig["AWSAccessKey"],
                    appConfig["AWSSecretKey"]
                    ) as AmazonS3Client;

            PutBucketRequest request = new PutBucketRequest();
            request.WithBucketName(bucketName);
            
            PutBucketResponse response = client.PutBucket(request);
            Console.WriteLine("AmazonId2: " + response.AmazonId2);
            Console.WriteLine("Reponse: " + response.ResponseXml);

            foreach (S3Bucket bucket in client.ListBuckets().Buckets)
                Console.WriteLine(bucket.BucketName);

        }

        public static void PutS3ItemInBucket(string path, string bucketName)
        {
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonS3Client client = AWSClientFactory.CreateAmazonS3Client(
                    appConfig["AWSAccessKey"],
                    appConfig["AWSSecretKey"]
                    ) as AmazonS3Client;

            PutObjectRequest request = new PutObjectRequest();
            request.WithFilePath(path);
            request.WithBucketName(bucketName);
            PutObjectResponse response = client.PutObject(request);

            ListObjectsRequest listRequest = new ListObjectsRequest();
            listRequest.WithBucketName(bucketName);
            foreach (S3Object obj in client.ListObjects(listRequest).S3Objects)
                Console.WriteLine("Object.Key: " + obj.Key + "  Object.LastModified: " + obj.LastModified);
            
        }

        public static void PutS3CanonicalUserIdACL(string canonicalUserId, string bucket, string file)
        {
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonS3Client client = AWSClientFactory.CreateAmazonS3Client(
                    appConfig["AWSAccessKey"],
                    appConfig["AWSSecretKey"]
                    ) as AmazonS3Client;

            SetACLRequest request = new SetACLRequest();
            request.BucketName = bucket;
            request.Key = file;
            
            S3AccessControlList acl = new S3AccessControlList();
            S3Grant grant = new S3Grant();
            S3Grantee grantee = new S3Grantee();         
            grantee.WithCanonicalUser(canonicalUserId, "CF_OAI_CUID_on_" + bucket + "-" + file);
            grant.Grantee = grantee;
            grant.Permission = S3Permission.READ;
            acl.Grants.Add(grant);
            
            Owner owner = new Owner();
            owner.WithId(appConfig["OwnerId"]);
            owner.DisplayName = "aws-dr-techwriters";
            acl.Owner = owner;

            try
            {
                request.ACL = acl;
                SetACLResponse respose = client.SetACL(request);
                Console.WriteLine("Response XML: " + respose.ResponseXml);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            
        }

        public static string ListObjectsWithOwner(string bucketName, string fileName)
        {
            NameValueCollection appConfig = ConfigurationManager.AppSettings;
            AmazonS3 client = AWSClientFactory.CreateAmazonS3Client(
                    appConfig["AWSAccessKey"],
                    appConfig["AWSSecretKey"]
                    );
            ListObjectsRequest listRequest = new ListObjectsRequest();
            listRequest.WithBucketName(bucketName);
            foreach (S3Object obj in client.ListObjects(listRequest).S3Objects)
            {
                Console.WriteLine("Object.Key: " + obj.Key + "  Object.LastModified: " + obj.LastModified);
                if (obj.Key == fileName)
                {
                    Console.WriteLine(fileName + " Owner Id: " + obj.Owner.Id);
                    return obj.Owner.Id;
                }
            }
            return "### " + fileName + " Not found";
        }

        public static string CreatePolicyStatement(string policyStmnt, string resourceUrl, 
                               DateTime startTime, DateTime endTime, string ipAddress)
        {
            // Create the policy statement.
            FileStream streamPolicy = new FileStream(policyStmnt, FileMode.Open, FileAccess.Read);
            using (StreamReader reader = new StreamReader(streamPolicy))
            {
                string strPolicy = reader.ReadToEnd();

                TimeSpan startTimeSpanFromNow = (startTime - DateTime.Now);
                TimeSpan endTimeSpanFromNow = (endTime - DateTime.Now);
                TimeSpan intervalStart = 
                    (DateTime.UtcNow.Add(startTimeSpanFromNow)) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                TimeSpan intervalEnd = 
                    (DateTime.UtcNow.Add(endTimeSpanFromNow)) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                
                int startTimestamp = (int)intervalStart.TotalSeconds; // START_TIME
                int endTimestamp = (int)intervalEnd.TotalSeconds;  // END_TIME

                if (startTimestamp > endTimestamp)
                    return "Error!";

                // Replace variables in the policy statement.
                strPolicy = strPolicy.Replace("RESOURCE", resourceUrl);
                strPolicy = strPolicy.Replace("START_TIME", startTimestamp.ToString());
                strPolicy = strPolicy.Replace("END_TIME", endTimestamp.ToString());
                strPolicy = strPolicy.Replace("IP_ADDRESS", ipAddress);
                strPolicy = strPolicy.Replace("EXPIRES", endTimestamp.ToString());
                return strPolicy;
            }   
        }

        public static TimeSpan GetDuration(string units, string numUnits)
        {
            TimeSpan timeSpanInterval = new TimeSpan();
            switch (units)
            {
                case "seconds":
                    timeSpanInterval = new TimeSpan(0, 0, 0, int.Parse(numUnits));
                    break;
                case "minutes":
                    timeSpanInterval = new TimeSpan(0, 0, int.Parse(numUnits), 0);
                    break;
                case "hours":
                    timeSpanInterval = new TimeSpan(0, int.Parse(numUnits), 0 ,0);
                    break;
                case "days":
                    timeSpanInterval = new TimeSpan(int.Parse(numUnits),0 ,0 ,0);
                    break;
                default:
                    Console.WriteLine("Invalid time units; use seconds, minutes, hours, or days");
                    break;
            }
            return timeSpanInterval;
        }

        private static TimeSpan GetDurationByUnits(string durationUnits, string startIntervalFromNow)
        {
            TimeSpan timeSpanInterval = new TimeSpan();
            switch (durationUnits)
            {
                case "seconds":
                    timeSpanInterval = new TimeSpan(0, 0, int.Parse(startIntervalFromNow));
                    break;
                case "minutes":
                    timeSpanInterval = new TimeSpan(0, int.Parse(startIntervalFromNow), 0);
                    break;
                case "hours":
                    timeSpanInterval = new TimeSpan(int.Parse(startIntervalFromNow), 0, 0);
                    break;
                case "days":
                    timeSpanInterval = new TimeSpan(int.Parse(startIntervalFromNow), 0, 0, 0);
                    break;
                default:
                    timeSpanInterval = new TimeSpan(0, 0, 0, 0);
                    break;
            }
            return timeSpanInterval;
        }

        public static string CopyExpirationTimeFromPolicy(string policyStatement)
        {
            int startExpiration = policyStatement.IndexOf("EpochTime");
            string strExpirationRough = policyStatement.Substring(startExpiration + "EpochTime".Length);
            char[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
            List<char> listDigits = new List<char>(digits);
            StringBuilder buildExpiration = new StringBuilder(20);
            foreach (char c in strExpirationRough)
            {
                if (listDigits.Contains(c))
                    buildExpiration.Append(c);
            }
            return buildExpiration.ToString();   
        }

        public static void ListMethods()
        {
            MethodInfo[] methodInfos =
                            typeof(Program).GetMethods(BindingFlags.Public | BindingFlags.Static);

            foreach (MethodInfo methodInfo in methodInfos)
            {
                Console.WriteLine("Method: " + methodInfo.Name);
                Console.Write("Arguments: ");
                foreach (ParameterInfo parInfo in methodInfo.GetParameters())
                    Console.Write(parInfo.Name + " ");
                Console.WriteLine("\n");
            }
            Console.WriteLine("Call the application using a method name and arguments as listed. \n Any key to end... ");
            Console.Read();
            return;
        }
    }
}
