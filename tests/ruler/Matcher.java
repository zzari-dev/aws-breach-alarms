import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import software.amazon.event.ruler.Machine;

/**
 * Reads JSON lines {"id", "pattern", "event"} from stdin and prints "id\ttrue|false"
 * using the same matching engine as Amazon EventBridge. Invalid patterns print "id\terror\t<msg>".
 */
public class Matcher {
    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) continue;
            JsonNode c = mapper.readTree(line);
            String id = c.get("id").asText();
            try {
                Machine machine = Machine.builder().build();
                machine.addRule("r", mapper.writeValueAsString(c.get("pattern")));
                boolean hit = !machine.rulesForJSONEvent(c.get("event")).isEmpty();
                System.out.println(id + "\t" + hit);
            } catch (Exception e) {
                System.out.println(id + "\terror\t" + e.getMessage().replace('\n', ' '));
            }
        }
    }
}
