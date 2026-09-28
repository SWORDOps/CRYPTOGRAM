/*
 * CRYPTOGRAM Stylometry Shield
 * Anonymizes text to prevent writing-pattern fingerprinting.
 *
 * Ports the rule-based anonymization from the desktop C++ implementation
 * (data_stylometry_shield.cpp): synonym substitution, punctuation variation,
 * sentence restructuring, filler word adjustment, and capitalization variation.
 */
package org.telegram.messenger.cryptogram;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class StylometryShield {

    public enum Strength { Light, Medium, Heavy }

    private static final StylometryShield INSTANCE = new StylometryShield();
    private final Random rng = new Random();

    private Strength strength = Strength.Medium;
    private boolean enabled = false;

    private static final Map<String, List<String>> SYNONYMS = new HashMap<>();
    private static final List<String> FILLERS = Arrays.asList(
        "like", "sort of", "kind of", "you know", "I mean",
        "honestly", "basically", "to be fair");
    private static final List<String> STYLE_MARKERS = Arrays.asList(
        "literally", "obviously", "clearly", "naturally",
        "of course", "needless to say");
    private static final List<String> EM_DASH_REPLACEMENTS = Arrays.asList(
        ", ", " - ", "; ");

    static {
        SYNONYMS.put("hello", Arrays.asList("hey", "hi there", "greetings"));
        SYNONYMS.put("hi", Arrays.asList("hey", "hello", "yo"));
        SYNONYMS.put("yes", Arrays.asList("yeah", "yep", "indeed", "correct"));
        SYNONYMS.put("no", Arrays.asList("nope", "nah", "negative"));
        SYNONYMS.put("good", Arrays.asList("great", "fine", "solid", "decent"));
        SYNONYMS.put("bad", Arrays.asList("poor", "rough", "subpar"));
        SYNONYMS.put("very", Arrays.asList("really", "quite", "extremely"));
        SYNONYMS.put("really", Arrays.asList("very", "truly", "genuinely"));
        SYNONYMS.put("big", Arrays.asList("large", "huge", "sizable"));
        SYNONYMS.put("small", Arrays.asList("tiny", "little", "compact"));
        SYNONYMS.put("fast", Arrays.asList("quick", "rapid", "swift"));
        SYNONYMS.put("slow", Arrays.asList("sluggish", "gradual", "unhurried"));
        SYNONYMS.put("important", Arrays.asList("crucial", "key", "significant"));
        SYNONYMS.put("think", Arrays.asList("believe", "reckon", "suppose"));
        SYNONYMS.put("know", Arrays.asList("realize", "understand", "grasp"));
        SYNONYMS.put("want", Arrays.asList("need", "would like", "desire"));
        SYNONYMS.put("get", Arrays.asList("obtain", "acquire", "receive"));
        SYNONYMS.put("make", Arrays.asList("create", "produce", "build"));
        SYNONYMS.put("use", Arrays.asList("utilize", "employ", "leverage"));
        SYNONYMS.put("help", Arrays.asList("assist", "support", "aid"));
        SYNONYMS.put("start", Arrays.asList("begin", "commence", "initiate"));
        SYNONYMS.put("end", Arrays.asList("finish", "conclude", "wrap up"));
        SYNONYMS.put("try", Arrays.asList("attempt", "endeavor", "give it a shot"));
        SYNONYMS.put("need", Arrays.asList("require", "could use", "must have"));
        SYNONYMS.put("like", Arrays.asList("enjoy", "appreciate", "favor"));
        SYNONYMS.put("look", Arrays.asList("seem", "appear", "glance"));
        SYNONYMS.put("find", Arrays.asList("discover", "locate", "identify"));
        SYNONYMS.put("tell", Arrays.asList("say", "inform", "mention"));
        SYNONYMS.put("show", Arrays.asList("display", "reveal", "present"));
        SYNONYMS.put("work", Arrays.asList("function", "operate", "perform"));
        SYNONYMS.put("call", Arrays.asList("phone", "ring", "contact"));
        SYNONYMS.put("buy", Arrays.asList("purchase", "acquire", "pick up"));
        SYNONYMS.put("eat", Arrays.asList("consume", "have", "grab"));
        SYNONYMS.put("go", Arrays.asList("head", "proceed", "move"));
        SYNONYMS.put("come", Arrays.asList("arrive", "show up", "appear"));
        SYNONYMS.put("see", Arrays.asList("notice", "spot", "observe"));
        SYNONYMS.put("say", Arrays.asList("state", "express", "mention"));
        SYNONYMS.put("great", Arrays.asList("excellent", "fantastic", "awesome"));
        SYNONYMS.put("okay", Arrays.asList("alright", "fine", "acceptable"));
        SYNONYMS.put("sure", Arrays.asList("certainly", "absolutely", "definitely"));
        SYNONYMS.put("thanks", Arrays.asList("appreciate it", "much obliged", "cheers"));
        SYNONYMS.put("sorry", Arrays.asList("apologies", "my bad", "regret that"));
        SYNONYMS.put("maybe", Arrays.asList("perhaps", "possibly", "might"));
        SYNONYMS.put("now", Arrays.asList("currently", "at the moment", "presently"));
        SYNONYMS.put("later", Arrays.asList("afterward", "subsequently", "in a bit"));
        SYNONYMS.put("today", Arrays.asList("this day", "right now", "as we speak"));
        SYNONYMS.put("tomorrow", Arrays.asList("the next day", "soon enough", "shortly"));
        SYNONYMS.put("always", Arrays.asList("constantly", "invariably", "every time"));
        SYNONYMS.put("never", Arrays.asList("not once", "at no point", "rarely if ever"));
        SYNONYMS.put("often", Arrays.asList("frequently", "regularly", "commonly"));
        SYNONYMS.put("however", Arrays.asList("though", "but still", "that said"));
        SYNONYMS.put("because", Arrays.asList("since", "as", "given that"));
        SYNONYMS.put("although", Arrays.asList("though", "even so", "despite that"));
        SYNONYMS.put("therefore", Arrays.asList("so", "thus", "hence"));
        SYNONYMS.put("finally", Arrays.asList("lastly", "in the end", "at last"));
        SYNONYMS.put("actually", Arrays.asList("in fact", "as it happens", "truthfully"));
        SYNONYMS.put("basically", Arrays.asList("essentially", "fundamentally", "in essence"));
        SYNONYMS.put("probably", Arrays.asList("likely", "most likely", "chances are"));
    }

    private static final Pattern WORD_PATTERN = Pattern.compile("\\b(\\w+)\\b");
    private static final Pattern SENTENCE_SPLIT = Pattern.compile("([.!?]+\\s*)");

    private StylometryShield() {}

    public static StylometryShield getInstance() { return INSTANCE; }

    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isEnabled() { return enabled; }

    public void setStrength(Strength s) { this.strength = s; }
    public Strength getStrength() { return strength; }

    /**
     * Anonymize text to reduce stylometric fingerprinting.
     * Returns the original text if the shield is disabled.
     */
    public String anonymize(String text) {
        if (!enabled || text == null || text.isEmpty()) {
            return text;
        }
        String result = applySynonymSubstitution(text);
        if (strength == Strength.Medium || strength == Strength.Heavy) {
            result = applyPunctuationVariation(result);
            result = applySentenceRestructuring(result);
        }
        if (strength == Strength.Heavy) {
            result = applyFillerWordAdjustment(result);
            result = applyStyleMarkerRemoval(result);
            result = applyCapitalizationVariation(result);
        }
        return result;
    }

    private String applySynonymSubstitution(String text) {
        int probability = strength.ordinal() * 30 + 20;
        Matcher m = WORD_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String word = m.group(1);
            String lower = word.toLowerCase();
            List<String> syns = SYNONYMS.get(lower);
            if (syns != null && rng.nextInt(100) < probability) {
                String replacement = syns.get(rng.nextInt(syns.size()));
                if (Character.isUpperCase(word.charAt(0))) {
                    replacement = Character.toUpperCase(replacement.charAt(0)) + replacement.substring(1);
                }
                m.appendReplacement(sb, replacement);
            } else {
                m.appendReplacement(sb, word);
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String applyPunctuationVariation(String text) {
        // Replace em-dashes with random alternatives
        String result = text.replace("—", EM_DASH_REPLACEMENTS.get(rng.nextInt(EM_DASH_REPLACEMENTS.size())));
        // Occasionally vary exclamation marks
        if (rng.nextInt(3) == 0) {
            result = result.replaceAll("!", ".");
        }
        return result;
    }

    private String applySentenceRestructuring(String text) {
        String[] parts = SENTENCE_SPLIT.split(text, -1);
        if (parts.length < 2) return text;
        List<String> sentences = new ArrayList<>();
        Matcher m = SENTENCE_SPLIT.matcher(text);
        int lastEnd = 0;
        while (m.find()) {
            sentences.add(text.substring(lastEnd, m.end()));
            lastEnd = m.end();
        }
        if (lastEnd < text.length()) {
            sentences.add(text.substring(lastEnd));
        }
        if (sentences.size() < 2) return text;

        List<String> modified = new ArrayList<>();
        String[] connectors = {" and ", ", and ", "; ", " — "};
        for (String sentence : sentences) {
            String s = sentence.trim();
            if (s.length() < 40 && rng.nextInt(3) == 0 && !modified.isEmpty()) {
                String connector = connectors[rng.nextInt(connectors.length)];
                modified.set(modified.size() - 1,
                    modified.get(modified.size() - 1).trim() + connector + s);
            } else {
                modified.add(sentence);
            }
        }
        return String.join("", modified);
    }

    private String applyFillerWordAdjustment(String text) {
        // Occasionally insert filler words after commas
        if (rng.nextInt(3) != 0) return text;
        String filler = FILLERS.get(rng.nextInt(FILLERS.size()));
        return text.replaceFirst(", ", ", " + filler + ", ");
    }

    private String applyStyleMarkerRemoval(String text) {
        String result = text;
        for (String marker : STYLE_MARKERS) {
            result = result.replaceAll("(?i)\\b" + Pattern.quote(marker) + "\\b,?\\s*", "");
        }
        return result;
    }

    private String applyCapitalizationVariation(String text) {
        // Occasionally lowercase the first letter of a sentence
        if (rng.nextInt(4) != 0) return text;
        Matcher m = Pattern.compile("(^|[.!?]\\s+)([A-Z])").matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            if (rng.nextInt(3) == 0) {
                m.appendReplacement(sb, m.group(1) + m.group(2).toLowerCase());
            } else {
                m.appendReplacement(sb, m.group());
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
