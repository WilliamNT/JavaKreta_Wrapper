import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;
class KretaApi {
    public static void main(String[] args) {
        Kreta kreta = new Kreta("USERNAME", "PASSWORD", "bkszc-pogany", "e-kreta.hu");
        System.out.println("It works!");

        System.out.println(kreta.getAccessToken());
        // System.out.println(kreta.fetchInstituteList());
    }

    public static class Endpoints {
        /**
         * All of the known E-KRÉTA API endpoints.
         * 
         * Reference: https://thegergo02.github.io/settings.json
         */

        // Domains
        String INSTITUTE_SUBDOMAIN;
        String KRETA_DOMAIN;
        String INSTITUTE_DOMAIN = null;
        private final String IDENTITY_PROVIDER = "https://idp.e-kreta.hu";
        private final String ADMINISTRATION = "https://eugyintezes.e-kreta.hu";
        private final String FILES = "https://files.e-kreta.hu";
        
        // Endpoints
        private final String TOKEN = "/connect/token";
        private final String NONCE = "/nonce";
        private final String NOTES = "/ellenorzo/V3/Sajat/Feljegyzesek";
        private final String EVENTS = "/ellenorzo/V3/Sajat/FaliujsagElemek";
        private final String STUDENT_INFO = "/ellenorzo/V3/Sajat/TanuloAdatlap";
        private final String EVALUATIONS = "/ellenorzo/V3/Sajat/Ertekelesek";
        private final String ABSENCES = "/ellenorzo/V3/Sajat/Mulasztasok";
        private final String CLASS_GROUPS = "/ellenorzo/V3/Sajat/OsztalyCsoportok";
        private final String CLASS_AVERAGES = "/V3/Sajat/Ertekelesek/Atlagok/OsztalyAtlagok";
        private final String TIMETABLE = "/ellenorzo/V3/Sajat/OrarendElemek";
        private final String ANNOUNCED_TESTS = "/ellenorzo/V3/Sajat/BejelentettSzamonkeresek";
        private final String HOMEWORK = "/ellenorzo/V3/Sajat/HaziFeladatok";
        //private final String HOMEWORK_DONE = "/ellenorzo/V3/Sajat/HaziFeladatok/Megoldva";    removed from the API
        private final String CAPABILITIES = "/ellenorzo/V3/Sajat/Intezmenyek";
        private final String SUBMIT_MESSAGE = "/api/v1/kommunikacio/uzenetek";
        private final String RECIPIENT_CATEGORIES = "/api/v1/adatszotarak/cimzetttipusok";
        private final String AVAILABLE_CATEGORIES = "/api/v1/kommunikacio/cimezhetotipusok";
        private final String RECIPIENT_TEACHERS = "/api/v1/kreta/alkalmazottak/tanar";
        private final String SUBMIT_ATTACHMENT = "/ideiglenesfajlok";
        private final String TRASH_MESSAGE = "/api/v1/kommunikacio/postaladaelemek/kuka";
        private final String DELETE_MESSAGE = "/api/v1/kommunikacio/postaladaelemek/torles";

        // Dynamic endpoints
        public String getMessagesEndpoint(String category) { 
            if (category == "beerkezett" || category == "elkuldott" || category == "torolt") {
                return "/api/v1/kommunikacio/postaladaelemek/" + category.toLowerCase();
            } else {
                throw new IllegalArgumentException("Invalid category \"" + category + "\" for message endpoint. Please choose from \"beerkezett\", \"elkuldott\" or \"torolt\".");
            }
        }

        public Endpoints(String subdomain, String kreta_domain) {
            if (subdomain.endsWith(".")) {
                INSTITUTE_SUBDOMAIN = subdomain;
            } else {
                INSTITUTE_SUBDOMAIN = subdomain + ".";
            }
            
            KRETA_DOMAIN = kreta_domain;
            INSTITUTE_DOMAIN = INSTITUTE_SUBDOMAIN + KRETA_DOMAIN;
        }
    }

    private static class Helpers {
        public static String getRequest(String url) {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                return response.body();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public static String generateHMACSignature(byte[] key, String message) {
            String hash = null;

            try {
                hash = SHA512Hasher(message);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

            return hash;
        }
 
        private static String SHA512Hasher(String stringToHash) throws NoSuchAlgorithmException, UnsupportedEncodingException {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.reset();

            byte[] buffer = stringToHash.getBytes("UTF-8");
            messageDigest.update(buffer);

            byte[] digest = messageDigest.digest();
            String hexString = "";

            for (int i = 0; i < digest.length; i++) {
                hexString += Integer.toString((digest[i] & 0xff) + 0x100, 16).substring(1);
            }

            return hexString;
        }
    }

    public static class Exceptions {
        public static class InvalidClientException extends Exception {
            public InvalidClientException(int http_code, String server_response, String url, String data) {
                super("Invalid client ID. " + url + " returned HTTP status " + http_code + " with body:\n\t" + server_response +"\nRequest body:\n\t" + data);
            }
        }

        public static class UnknownInstituteException extends Exception {
            public UnknownInstituteException(String instituteCode) {
                super("Unknown institute \"" + instituteCode + "\". It's possible that the institute code (subdomain) is misspelled or that the E-KRÉTA API was updated to use a different formatting for the institute list (this is unlikely but can still happen). Please check for typos.");
            }
        }
    }

    public static class Kreta {
        String user;
        String password;
        String institute;
        Endpoints endpoints;
        String domain;

        // We need these to trick the mobile API into thinking that the requests
        // are sent from a student's smartphone
        // Latest userAgent, clientId, apiKey can be found on my server: https://depo.skiby.net/kreta/mobileAuthentication.json
        String userAgent = "hu.ekreta.student/1.0.5/Android/0/0";
        String clientId = "kreta-ellenorzo-mobile";
        String apiKey = "7856d350-1fda-45f5-822d-e1a2f3f1acf0";

        public Kreta(String kreta_user, String kreta_password, String kreta_institute, String kreta_domain) {
            user = kreta_user.toLowerCase();
            password = kreta_password;
            institute = kreta_institute.toLowerCase();
            endpoints = new Endpoints(kreta_institute, kreta_domain);
            domain = kreta_domain;
        }

        public String getAccessToken() {
            /**
             * Returns the access token required for authentication to the
             * E-KRÉTA API. To do this, it sends an HMAC signed request with
             * the username, password, institute code, grant_type and client_id
             * to the API.
            */
            byte[] key = {53, 75, 109, 112, 109, 103, 100, 53, 102, 74};
            String nonce = getNonce();
            String message = user.toLowerCase() + institute.toLowerCase() + nonce;

            // Reference: https://github.com/filc/naplo/blob/home_hidden_ids/filcnaplo/lib/api/nonce.dart
            String digest = Helpers.generateHMACSignature(key, message);

            String data = String.format("password=%s&institute_code=%s&grant_type=%s&userName=%s&client_id=%s", password, institute, "password", user, clientId);
            data = URLEncoder.encode(data, StandardCharsets.UTF_8);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoints.IDENTITY_PROVIDER + endpoints.TOKEN))
                    .setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    .setHeader("User-Agent", userAgent)
                    .setHeader("X-AuthorizationPolicy-Key", Base64.getEncoder().encodeToString(digest.getBytes()))
                    .setHeader("X-AuthorizationPolicy-Version", "v1")
                    .setHeader("X-AuthorizationPolicy-Nonce", nonce)
                    .POST(BodyPublishers.ofString(data))
                    .build();

            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                System.out.println(request.headers());
                System.out.println(data);
                if (response.statusCode() == 400) {
                    String url = endpoints.IDENTITY_PROVIDER + endpoints.TOKEN;
                    throw new Exceptions.InvalidClientException(response.statusCode(), response.body(), url, data);
                } else {
                    System.out.println(response.statusCode());
                    return response.body();
                }           

            } catch (InterruptedException | IOException | Exceptions.InvalidClientException e) {
                throw new RuntimeException(e);
            }
        }

        public String getNonce() {
            return Helpers.getRequest(endpoints.IDENTITY_PROVIDER + endpoints.NONCE);
        }

        /**
         * Yet to be implemented. Returns nothing at the moment.
        */
        public void refreshAccessToken() {}
        public void getUserDetails() {}
        public void getNotes() {}
        public void getEvents() {}
        public void getGrades() {}
        public void getAbsences() {}
        public void getClassGroups() {}
        public void getClassAverage() {}
        public void getTimetable() {}
        public void getAnnouncedExams() {}
        public void getHomeworks() {}

        // This feature is disabled globally
        // but the API endpoint is online
        public void getFinishedHomeworks() {}
        public void getInstitutes() {}

        public JSONArray fetchInstituteList() {
            /**
             * Fetches the list of institutes using the E-KRÉTA system and returns it as a JSONArray.
             */
            // Third party mirror API by Filc developers (source: https://github.com/filc/naplo/blob/664321bc21e999fab49c1071281744fae744f3db/filcnaplo/lib/api/client.dart#L16)

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://kretaglobalmobileapi2.ekreta.hu/api/v1/Institute"))
                    .setHeader("User-Agent", userAgent)
                    .setHeader("apiKey", apiKey)
                    .GET()
                    .build();

            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                return new JSONArray(response.body());
            } catch (InterruptedException | IOException e) {
                throw new RuntimeException(e);
            }
        }

        public JSONObject getCurrentInstituteDetails(JSONArray instituteList) throws Exceptions.UnknownInstituteException {
            /**
             * Returns the student's institute's details as a JSONObject.
             * It's basically a shortcut for the filterInstituteList() function.
             * 
             * If the institute can't be found it throws an UnknownInstituteException.
             */
            return filterInstituteList(instituteList, institute);
        }

        public JSONObject filterInstituteList(JSONArray instituteList, String instituteCode) throws Exceptions.UnknownInstituteException {
            /**
             * Filters the institute list for the specified institute code (subdomain) and returns the result as a JSONObject.
             * 
             * If the institute can't be found it throws an UnknownInstituteException.
             */

             // Alternative method: https://kretaglobalmobileapi.ekreta.hu/api/v1/Institute/INSTITUTE_ID
            JSONObject school = new JSONObject();
            for (int i = 0; i < instituteList.length(); i++) {
                JSONObject x = instituteList.getJSONObject(i);
                String url = x.getString("instituteCode");
                if (url.equals(institute)) {
                    school = x;
                    break;
                }
            }

            if (school.length() != 0) {
                return school;
            } else {
                throw new Exceptions.UnknownInstituteException(institute);
            }
        }
    }

    public static class Messaging {
        /**
         * Stores functions needed for messaging.
         */
        public void getMessages() {}

        public String getMessageUrl(int id) {
            // Endpoint not in the Endpoints class
            return "/api/v1/kommunikacio/postaladaelemek/" + id;
        }

        public String getAttachmentUrl(int AttachmentId) {
            // Endpoint not in the Endpoints class
            return "/v1/dokumentumok/uzenetek/" + AttachmentId;
        }

        public void sendMessage() {}
        public void getRecipientCategories() {}
        public void getAvailableCategories() {}
        public void getTeacherRecipients() {}
        public void submitAttachment() {}
        public void sendMessageToTrash() {}
        public void deleteMessage() {}
    }

    public static class Tools {
        /**
         * Stores utility functions like grade calculator
         */

        public static int calculateImaginaryAverage(int[] grades, int[] imaginaryGrades) {
            /**
             * Calculates the avarage if the student had imaginary grades
             * 
             * Example use case: the student has the grades 5, 3, 3, 4 and wonders
             * what their average would be if they received a 5. The official mobile
             * app and other community projects already have this feature.
             */

            return 0;
        }

        public static double calculateAverage(int[] grades) throws IllegalArgumentException {
            /**
             * Calculates the student's avarage. The official mobile app
             * and other community projects already have this feature.
             */

            if (grades.length > 0) {
                float x = 0;
                for (int grade : grades) {
                    if (grade >= 1 && grade <= 5) {
                        x += grade;
                    } else {
                        throw new IllegalArgumentException("Invalid grade \"" + grade + "\". Valid grades are 1, 2, 3, 4 and 5.");
                    }
                }

                float y =  x / grades.length;
                return Math.round(y * 100.0) / 100.0;
            } else {
                throw new IllegalArgumentException();
            }
        }

        public static int calculateScholarship(int[] grades) {
            /**
             * Returns the expected scholarship if the student keeps the current average.
             */

            return 0;
        }

        public static void exportGrades(Kreta kreta) {
            /**
             * Retrieves the grades the student received so far
             * and exports them to the disk
             */
        }
    }
}