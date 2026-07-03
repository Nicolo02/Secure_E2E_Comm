package protocol;

public class AntiReplay {

    private long lastAcceptedSeq = -1;

    public synchronized boolean isValid(long seqNumber) {
        if (seqNumber <= lastAcceptedSeq) {
            return false;
        }
        lastAcceptedSeq = seqNumber;
        return true;
    }

    public synchronized long getLastAcceptedSeq() {
        return lastAcceptedSeq;
    }
}