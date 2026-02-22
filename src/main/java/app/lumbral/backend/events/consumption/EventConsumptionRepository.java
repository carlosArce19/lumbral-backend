package app.lumbral.backend.events.consumption;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface EventConsumptionRepository extends JpaRepository<EventConsumption, UUID> {

    boolean existsByConsumerNameAndEventId(String consumerName, UUID eventId);
}
